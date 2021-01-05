# modsecurity-elastic-alert-notification

![License](https://img.shields.io/github/license/houtarou-dism/modsecurity-elastic-alert-notification)

This is a program that sends out alerts based on the ModSecurity log stored in Elasticsearch. The fields are based on ([https://github.com/houtarou-dism/modsecurity-logstash](https://github.com/houtarou-dism/modsecurity-logstash)). Used by AWS Lambda.

Slack is available as the destination for alerts.

## Usage

### common

Go to common directory.

```
cd ~/modsecurity-elastic-alert-notification/common
```

```
cp .env.example .env
```

Set environment variables to match your environment.

Environment variables can also be set in lambda, and when set in lambda, they take precedence over .env values.

[https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html)

```
vim .env
```

Install the required packages in the directory.

```
pip install boto3 requests python-dotenv -t .
```

Zip

```
zip -r slack-notification.zip .
```

### log-summary-batch

Go to log-summary-batch directory.

```
cd ~/modsecurity-elastic-alert-notification/log-summary-batch
```

```
cp .env.example .env
```

Set environment variables to match your environment,

Environment variables can also be set in lambda, and when set in lambda, they take precedence over .env values.

[https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html)

```
vim .env
```

Install the required packages in the directory.

```
pip install elasticsearch python-dotenv -t .
```

Zip

```
zip -r log-summary-batch.zip .
```

### anomaly-detection-batch

Go to anomaly-detection-batch directory.

```
cd ~/modsecurity-elastic-alert-notification/anomaly-detection-batch
```

```
cp .env.example .env
```

Set environment variables to match your environment,

Environment variables can also be set in lambda, and when set in lambda, they take precedence over .env values.

[https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html)

```
vim .env
```

Install the required packages in the directory.

```
pip install elasticsearch python-dotenv -t .
```

Zip

```
zip -r anomaly-detection-batch.zip .
```



