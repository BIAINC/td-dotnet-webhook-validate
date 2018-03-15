# TotalDiscovery C#/Dotnet webhook sig example

For an example payload, such as

```
{
   "id":"en_e86f0cc08fb978fdc45cfa96ca3fdcf2",
   "type":"event_notification",
   "api-version":"2018-01-01",
   "meta":{
      "request":{
         "type":"test.event",
         "event-time":"2018-02-12T00:38:02Z",
         "event-id":"evt_664deee4c06521e1e63549936c000a9c"
      }
   },
   "data":{
      "type":"hello",
      "attributes":{
         "ping":"2018-02-12T00:38:02Z"
      }
   }
}
```

(Note the above was formated nicely. The actual body of the webhook will not have line returns)

with the following header
`X-TD-Signature: t=1518396013,v1=5e74a4786626a887c7de42bdc072c9e6ca471cd6b7509247b9ddff6cdca48c15`

We take the timestamp from the header, which is the key `t` and the entire body and format into the following payload
`1518396013.{"id":"en_e86f0cc08fb978fdc45cfa96ca3fdcf2","type":"event_notification","api-version":"2018-01-01","meta":{"request":{"type":"test.event","event-time":"2018-02-12T00:38:02Z","event-id":"evt_664deee4c06521e1e63549936c000a9c"}},"data":{"type":"hello","attributes":{"ping":"2018-02-12T00:38:02Z"}}}`
and then HMAC SHA-256 that string with the provided secret. The result is placed into the `v1` key in the header.

If the values match, the signature is valid. However, to avoid replay issues, you should make sure that the timestamp is not older then 5 minutes
