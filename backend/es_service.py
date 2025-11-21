from elasticsearch import Elasticsearch
from datetime import datetime, timedelta

es = Elasticsearch("http://local:9200")

def search_logs(query: str, days: int, limit: int):
    index_pattern = "fortigate-*"
    start_date = datetime.now() - timedelta(days=days)

    es_query = {
        "size": limit,
        "query": {
            "bool": {
                "must": [{"query_string": {"query": query}}],
                "filter": [{"range": {"@timestamp": {"gte": start_date.isoformat()}}}]
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}]
    }

    res = es.search(index=index_pattern, body=es_query)
    return res["hits"]["hits"]
