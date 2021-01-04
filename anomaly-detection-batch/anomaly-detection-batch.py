import os
import re
import json
import requests
import datetime
import collections
from dotenv import load_dotenv
from elasticsearch import Elasticsearch


def get_audit_log_source_info(search_result):
    """search_resultからAudit logと送信元情報を取得します。

    search_resultから取得したAudit logと送信元情報を結合したものをListにまとめて返します。

    Args:
        search_result (dict): elastic searchから取得したドキュメント。

    Returns:
        [list]: Audit logと送信元情報をまとめたList。
    """

    log_list = []

    for document in search_result["hits"]["hits"]:
        for audit_log_num in document["_source"]["audit_log"]:
            log_list.append({**document["_source"]["audit_log"]
                             [str(audit_log_num)], **document["_source"]["source"]})

    return log_list


def get_access_denied_ip(search_result):
    """search_resultからアクセス拒否されたIPを取得します。

    Args:
        search_result (dict): elastic searchから取得したドキュメント。

    Returns:
        [list]: アクセス拒否IPをまとめたList
    """

    ip_list = []

    for log in get_audit_log_source_info(search_result):
        if "Access denied" in log["action"]:
            ip_list.append(log["ip"])

    return ip_list


def get_geo_ip(search_result):
    """search_resultからGeo IP情報を取得します。

    Args:
        search_result (dict): elastic searchから取得したドキュメント。

    Returns:
        [list]: Geo IP情報をまとめたList
    """

    geo_ip_list = {}

    for document in search_result["hits"]["hits"]:
        if document["_source"]["geoip"] != {}:
            geo_ip_list[document["_source"]["geoip"]
                        ["ip"]] = document["_source"]["geoip"]

    return geo_ip_list


def surveil_http_status(search_result):
    """500番台のエラーの情報を返します。

    500番台のエラーが閾値以上出ていた場合に、「HTTP Status Code」「HTTP Status Codeの回数」「設定している閾値」の情報を
    もったresponse_alertを返します。閾値以上出ていない場合はNoneを返します。

    Args:
        search_result (dict): elastic searchから取得したドキュメント。

    Returns:
        [dict, none]: 「HTTP Status Code」「HTTP Status Codeの回数」「設定している閾値」の情報 or None。
    """

    http_status_list = []
    response_alert = {}
    http_status_count_threshold = int(
        os.environ['HTTP_STATUS_COUNT_THRESHOLD'])
    http_pattern = re.compile(r'50[0-9]{1}')

    for document in search_result["hits"]["hits"]:
        if http_pattern.match(
                document["_source"]["response"]["headers"]["http_status"]):
            http_status_list.append(
                document["_source"]["response"]["headers"]["http_status"])

    http_status_collections = collections.Counter(http_status_list)

    for http_status in http_status_collections:
        if http_status_collections[http_status] >= http_status_count_threshold:
            response_alert["Alerting " + http_status] = {
                "HTTP Status": http_status,
                "Count": http_status_collections[http_status],
                "Threshold": http_status_count_threshold
            }

    return response_alert if response_alert != {} else None


def surveil_access_denied(search_result):
    """アクセス拒否されたIPの情報を返します。

    Access deniedが閾値以上出ていた場合に、「IP」「Access deniedされた回数」「設定している閾値」「Geo IP」の情報を
    もったresponse_alertを返します。Geo IP情報が存在しない場合は、Noneを返します。
    閾値以上出ていない場合はNoneを返します。

    Args:
        search_result (dict): elastic searchから取得したドキュメント。

    Returns:
        [dict, none]: 「IP」「Access deniedされた回数」「設定している閾値」「Geo IP」の情報 or None
    """

    response_alert = {}
    access_denied_ip_threshold = int(os.environ['ACCESS_DENIED_IP_THRESHOLD'])
    ip_list = collections.Counter(get_access_denied_ip(search_result))

    for ip in ip_list:
        if ip_list[ip] >= access_denied_ip_threshold:
            geo_ip = get_geo_ip(search_result)
            response_alert["Access denied " + ip] = {
                "IP": ip,
                "Count": ip_list[ip],
                "Threshold": access_denied_ip_threshold,
                "Geo IP": geo_ip[ip] if ip in geo_ip else None
            }

    return response_alert if response_alert != {} else None


def exception_response(ex, slack_webhook):
    """例外が発生した場合のレスポンスです。

    Args:
        ex (object): 例外情報
        slack_webhook (str): Slack WebHook URL
    """
    response_json = {
        "timestamp": (datetime.datetime.now()).strftime("%Y-%m-%d %H:%M:%S"),
        "message": "エラーが発生しました。",
        "detail": {
            "exception_message": str(ex)
        }
    }
    payload = {
        "attachments": [
            {
                "fallback": "Anomaly detection batch（Error occurred）",
                "pretext": json.dumps(response_json,
                                      indent=4, ensure_ascii=False)
            }
        ]
    }
    requests.post(slack_webhook, data=json.dumps(payload))


def main(event, context):

    load_dotenv()

    es = Elasticsearch(
        os.environ['ELASTICSEARCH_URL'],
        http_auth=(os.environ['ELASTICSEARCH_ID'],
                   os.environ['ELASTICSEARCH_PASSWORD'])
    )

    slack_webhook = os.environ['SLACK_URL']
    kibana_url = os.environ['KIBANA_URL']

    query = {
        "_source": [
            "date", "audit_log", "response", "source", "geoip"
        ],
        "query": {
            "range": {
                "@timestamp": {
                    "gte": "now-10m",
                    "lt": "now"
                }
            }
        }
    }

    try:
        search_result = es.search(index="nginx-*", body=query, size=10000)
    except Exception as ex:
        exception_response(ex, slack_webhook)
        es.close()
        return - 1

    http_status_surveillance = surveil_http_status(search_result)
    access_denied_surveillance = surveil_access_denied(search_result)

    if http_status_surveillance is None and access_denied_surveillance is None:
        es.close()
        return 0

    response_json = {
        "Kibana URL": kibana_url,
        "HTTP Status Anomaly detection alert": http_status_surveillance,
        "Access denied surveillance alert": access_denied_surveillance,
    }

    payload = {
        "attachments": [
            {
                "fallback": "Anomaly detection batch",
                "pretext": json.dumps(response_json,
                                      indent=4, ensure_ascii=False)
            }
        ]
    }

    requests.post(slack_webhook, data=json.dumps(payload))

    es.close()


if __name__ == "__main__":
    main({}, {})
