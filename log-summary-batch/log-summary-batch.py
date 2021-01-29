import os
import datetime
from dotenv import load_dotenv
from itertools import groupby
from collections import defaultdict
from elasticsearch import Elasticsearch


def get_audit_log(search_result):
    """search_resultからAudit logを取得します。

    search_resultから取得したAudit logをListにまとめて返します。

    Args:
        search_result (dict): elastic searchから取得したドキュメント。

    Returns:
        [list]: Audit logをまとめたList。
    """

    log_list = []

    for document in search_result["hits"]["hits"]:
        for audit_log_num in document["_source"]["audit_log"]:
            log_list.append(
                document["_source"]["audit_log"][str(audit_log_num)])

    return log_list


def detailed_attack_types(search_result):
    """アクセスの詳細を返します。

    Audit log IDをKeyにもつ、「Audit log IDの数」「重大度」「メッセージ」をdictで返します。

    Args:
        search_result (dict): elastic searchから取得したドキュメント。

    Returns:
        [dict]: 「Audit log IDの数」「重大度」「メッセージ」の情報
    """

    audit_log = defaultdict(list)
    response_json = {}

    for log in get_audit_log(search_result):
        audit_log[log["id"]].append([log["action"], log["message2"]])

    for log in audit_log:
        response_json[log] = {
            "Count": len(audit_log[log]),
            "Severity": audit_log[log][0][0],
            "Message": audit_log[log][0][1]
        }

    return response_json


def number_of_http_status_detections(search_result):
    """HTTP Status Codeの数を返します。

    各HTTP Status Codeの数をdictで返します。

    Args:
        search_result (dict): elastic searchから取得したドキュメント。

    Returns:
        [dict]]: 各HTTP Status Codeの数
    """

    status_list = []
    number_status_detections = {}

    for document in search_result["hits"]["hits"]:
        status_list.append(
            document["_source"]["response"]["headers"]["http_status"])

    status_list.sort()

    for key, status in groupby(status_list):
        number_status_detections[key] = len(list(status))

    return number_status_detections


def exception_response(ex):
    """例外が発生した場合のレスポンスです。

    Args:
        ex (object): 例外情報
    """
    response_json = {
        "timestamp": (datetime.datetime.now()).strftime("%Y-%m-%d %H:%M:%S"),
        "message": "エラーが発生しました。",
        "detail": {
            "Exception message": str(ex)
        }
    }

    return {
        "fallback": "Log summary batch（Error occurred）",
        "body": response_json
    }


def lambda_handler(event, context):

    load_dotenv()

    es = Elasticsearch(
        os.environ['ELASTICSEARCH_URL'],
        http_auth=(os.environ['ELASTICSEARCH_ID'],
                   os.environ['ELASTICSEARCH_PASSWORD'])
    )

    kibana_url = os.environ['KIBANA_URL']
    index_name = "nginx-" + (datetime.date.today() -
                             datetime.timedelta(days=1)).strftime("%Y-%m-%d")

    query = {
        "_source": [
            "date", "audit_log", "response"
        ]
    }

    try:
        search_result = es.search(index=index_name, body=query, size=10000)
    except Exception as ex:
        es.close()
        return exception_response(ex)

    response_json = {
        "Kibana URL": kibana_url,
        "Index Name": index_name,
        "Hits Total": search_result['hits']['total']['value'],
        "Shards": {
            "Total": search_result['_shards']['total'],
            "Successful": search_result['_shards']['successful'],
            "Skipped": search_result['_shards']['skipped'],
            "Failed": search_result['_shards']['failed']},
        "HTTP status code count": number_of_http_status_detections(search_result),
        "Detailed attack types": detailed_attack_types(search_result),
    }

    es.close()

    return {
        "fallback": "Log summary batch",
        "body": response_json
    }


if __name__ == "__main__":
    lambda_handler({}, {})
