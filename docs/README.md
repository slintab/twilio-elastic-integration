### Supported Events

| Event | Schema Version |
|---|---|
| ErrorLogs.Error | v1 |
| EngagementIntelligence.TranscriptEvent | v1 |
| Messaging.MessageStatus | v3 |
| Messaging.InboundMessageV1 | v1 |
| Studio.FlowExecutionEvent | v1 |
| Studio.FlowStepEvent | v1 |
| TaskRouter.WDSEvent | v1 |
| VideoInsights.VideoLogAnalyzerParticipantSummary | v1 |
| VideoInsights.VideoLogAnalyzerRoomSummary | v1 |
| VoiceInsights.CallEvent | v1 |
| VoiceInsights.CallSummary | v2 |
| VoiceInsights.ConferenceParticipantSummary | v1 |
| VoiceInsights.ConferenceSummary | v1 |
| SuperSim.ConnectionEvent | v2 |


### Sample event

An example event for `events` looks as following:

```json
{
    "_index": ".ds-logs-twilio.events-default-2022.07.30-000001",
    "_id": "dnxlVIIBgeK1Ltnux3Gc",
    "_version": 1,
    "_score": 0,
    "_source": {
        "agent": {
            "name": "docker-fleet-agent",
            "id": "db4ad615-71f8-4ee2-b05d-ce6a0a4e29df",
            "type": "filebeat",
            "ephemeral_id": "1fde8209-1a96-4e31-9642-14e5711b0833",
            "version": "8.3.2"
        },
        "elastic_agent": {
            "id": "db4ad615-71f8-4ee2-b05d-ce6a0a4e29df",
            "version": "8.3.2",
            "snapshot": false
        },
        "tags": [
            "twilio-event",
            "forwarded"
        ],
        "input": {
            "type": "http_endpoint"
        },
        "@timestamp": "2022-07-31T13:15:00.707Z",
        "ecs": {
            "version": "8.0.0"
        },
        "data_stream": {
            "namespace": "default",
            "type": "logs",
            "dataset": "twilio.events"
        },
        "twilio": {
            "Messaging": {
                "MessageStatus": {
                    "messageStatus": "SENT",
                    "apiVersion": "2010-04-01",
                    "eventName": "com.twilio.messaging.message.sent",
                    "from": "+441234567890",
                    "to": "+440987654321",
                    "accountSid": "AC12345678900987654321",
                    "messageSid": "SM12345678900987654321",
                    "timestamp": "2022-07-31T13:15:00.707Z"
                }
            },
            "datacontenttype": "application/json",
            "specversion": "1.0",
            "source": "/2010-04-01/Accounts/AC12345678900987654321/Messages/SM12345678900987654321.json",
            "id": "EZ1234567890987654321",
            "time": "2022-07-31T13:15:00.707Z",
            "type": "com.twilio.messaging.message.sent",
            "dataschema": "https://events-schemas.twilio.com/Messaging.MessageStatus/3"
        },
        "event": {
            "agent_id_status": "verified",
            "ingested": "2022-07-31T13:15:32Z",
            "kind": [
                "event"
            ],
            "action": "com.twilio.messaging.message.sent",
            "type": [
                "info"
            ],
            "dataset": "twilio.events"
        }
    },
    "fields": {
        "twilio.time": [
            "2022-07-31T13:15:00.707Z"
        ],
        "elastic_agent.version": [
            "8.3.2"
        ],
        "twilio.Messaging.MessageStatus.eventName": [
            "com.twilio.messaging.message.sent"
        ],
        "agent.type": [
            "filebeat"
        ],
        "twilio.Messaging.MessageStatus.messageSid": [
            "SM12345678900987654321"
        ],
        "twilio.specversion": [
            "1.0"
        ],
        "event.module": [
            "twilio"
        ],
        "twilio.datacontenttype": [
            "application/json"
        ],
        "twilio.Messaging.MessageStatus.accountSid": [
            "AC12345678900987654321"
        ],
        "twilio.Messaging.MessageStatus.messageStatus": [
            "SENT"
        ],
        "twilio.dataschema": [
            "https://events-schemas.twilio.com/Messaging.MessageStatus/3"
        ],
        "agent.name": [
            "docker-fleet-agent"
        ],
        "elastic_agent.snapshot": [
            false
        ],
        "event.agent_id_status": [
            "verified"
        ],
        "event.kind": [
            "event"
        ],
        "twilio.id": [
            "EZf4688ba7bbbd5f8421c13b23b2cc6bcb"
        ],
        "twilio.source": [
            "/2010-04-01/Accounts/AC12345678900987654321/Messages/SM12345678900987654321.json"
        ],
        "twilio.Messaging.MessageStatus.to": [
            "+440987654321"
        ],
        "elastic_agent.id": [
            "db4ad615-71f8-4ee2-b05d-ce6a0a4e29df"
        ],
        "data_stream.namespace": [
            "default"
        ],
        "input.type": [
            "http_endpoint"
        ],
        "twilio.Messaging.MessageStatus.from": [
            "+441234567890"
        ],
        "twilio.Messaging.MessageStatus.apiVersion": [
            "2010-04-01"
        ],
        "data_stream.type": [
            "logs"
        ],
        "tags": [
            "twilio-event",
            "forwarded"
        ],
        "twilio.Messaging.MessageStatus.timestamp": [
            "2022-07-31T13:15:00.707Z"
        ],
        "twilio.type": [
            "com.twilio.messaging.message.sent"
        ],
        "event.action": [
            "com.twilio.messaging.message.sent"
        ],
        "event.ingested": [
            "2022-07-31T13:15:32.000Z"
        ],
        "@timestamp": [
            "2022-07-31T13:15:00.707Z"
        ],
        "agent.id": [
            "db4ad615-71f8-4ee2-b05d-ce6a0a4e29df"
        ],
        "ecs.version": [
            "8.0.0"
        ],
        "event.type": [
            "info"
        ],
        "data_stream.dataset": [
            "twilio.events"
        ],
        "agent.ephemeral_id": [
            "1fde8209-1a96-4e31-9642-14e5711b0833"
        ],
        "agent.version": [
            "8.3.2"
        ],
        "event.dataset": [
            "twilio.events"
        ]
    }
}
```


### Exported fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| input.type | Input type. | keyword |
| log.offset | Log offset | long |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| twilio.EngagementIntelligence.TranscriptEvent.account_sid | Account that generated the event | keyword |
| twilio.EngagementIntelligence.TranscriptEvent.date_created | Creation date of the event | date |
| twilio.EngagementIntelligence.TranscriptEvent.service_sid | Service identifier | keyword |
| twilio.EngagementIntelligence.TranscriptEvent.transcript_sid | Transcript identifier | keyword |
| twilio.ErrorLogs.Error.account_sid | The accound SID the debug event belongs to | keyword |
| twilio.ErrorLogs.Error.correlation_sid | The correlation SID of the debug event | keyword |
| twilio.ErrorLogs.Error.date_created | The date the debug event was created | keyword |
| twilio.ErrorLogs.Error.error_code | The Twilio error code which is associated with the debug event | keyword |
| twilio.ErrorLogs.Error.level | The log level of the debug event | keyword |
| twilio.ErrorLogs.Error.master_account_sid | The account SID of the parent account the debug event belongs to | keyword |
| twilio.ErrorLogs.Error.payload | The payload of the debug event | keyword |
| twilio.ErrorLogs.Error.product_name | The Twilio product which created the debug event | keyword |
| twilio.ErrorLogs.Error.request_sid | The request SID  of the debug event | keyword |
| twilio.ErrorLogs.Error.service_sid | The service SID of the debug event | keyword |
| twilio.ErrorLogs.Error.sid | SID for the debug event | keyword |
| twilio.Messaging.InboundMessageV1.accountSid | Id of the Twilio account which was used while sending the message | keyword |
| twilio.Messaging.InboundMessageV1.body | Body of the message | keyword |
| twilio.Messaging.InboundMessageV1.eventName | Description of this event | keyword |
| twilio.Messaging.InboundMessageV1.from | From number of the message | keyword |
| twilio.Messaging.InboundMessageV1.fromCity | Source city | keyword |
| twilio.Messaging.InboundMessageV1.fromCountry | Source country | keyword |
| twilio.Messaging.InboundMessageV1.fromState | Source state | keyword |
| twilio.Messaging.InboundMessageV1.fromZip | Source zip code | keyword |
| twilio.Messaging.InboundMessageV1.messageSid | Id of message which the event belongs to | keyword |
| twilio.Messaging.InboundMessageV1.numMedia | Number of media | integer |
| twilio.Messaging.InboundMessageV1.numSegments | Number of segments | integer |
| twilio.Messaging.InboundMessageV1.timestamp | Time of the event | date |
| twilio.Messaging.InboundMessageV1.to | To number of the message | keyword |
| twilio.Messaging.InboundMessageV1.toCity | Destination city | keyword |
| twilio.Messaging.InboundMessageV1.toCountry | Destination country | keyword |
| twilio.Messaging.InboundMessageV1.toState | Destination state | keyword |
| twilio.Messaging.InboundMessageV1.toZip | Destination zip code | keyword |
| twilio.Messaging.MessageStatus.accountSid | Id of the Twilio account which was used while sending the message | keyword |
| twilio.Messaging.MessageStatus.apiVersion | Twilio API version used while sending the message | keyword |
| twilio.Messaging.MessageStatus.body | Body of the message | keyword |
| twilio.Messaging.MessageStatus.errorCode | This field is set to the error code if delivery wasn't successful and an error has occurred | integer |
| twilio.Messaging.MessageStatus.eventName | Description of this event | keyword |
| twilio.Messaging.MessageStatus.from | From number of the message | keyword |
| twilio.Messaging.MessageStatus.messageSid | Id of message which the event belongs to | keyword |
| twilio.Messaging.MessageStatus.messageStatus | The status of the message. Message delivery information is reflected in message status. The possible values are QUEUED, FAILED, SENT, DELIVERED, UNDELIVERED, READ. | keyword |
| twilio.Messaging.MessageStatus.messagingServiceSid | This field is set to id of messaging service used if the message is sent through a messaging service | keyword |
| twilio.Messaging.MessageStatus.statusCallBackUrl | Status callback url | keyword |
| twilio.Messaging.MessageStatus.timestamp | Time of the event | date |
| twilio.Messaging.MessageStatus.to | To number of the message | keyword |
| twilio.Studio.FlowExecutionEvent.account_sid | Account SID from Event | keyword |
| twilio.Studio.FlowExecutionEvent.contact_channel_address | Address of contact channel | keyword |
| twilio.Studio.FlowExecutionEvent.date_created | Execution creation date | date |
| twilio.Studio.FlowExecutionEvent.date_updated | Date updated for execution event | date |
| twilio.Studio.FlowExecutionEvent.ended_reason | Reason to end execution | keyword |
| twilio.Studio.FlowExecutionEvent.execution_sid | Execution SID from Event | keyword |
| twilio.Studio.FlowExecutionEvent.flow_revision | Revision number of the Flow that was used to handle this Execution | integer |
| twilio.Studio.FlowExecutionEvent.flow_sid | Flow SID from Event | keyword |
| twilio.Studio.FlowExecutionEvent.started_by | SID of the resource that initiated the Execution | keyword |
| twilio.Studio.FlowExecutionEvent.status | Execution Status | keyword |
| twilio.Studio.FlowStepEvent.account_sid | Account SID from Event | keyword |
| twilio.Studio.FlowStepEvent.date_created | Step creation date | date |
| twilio.Studio.FlowStepEvent.execution_sid | Execution SID from Event | keyword |
| twilio.Studio.FlowStepEvent.flow_sid | Flow SID from Event | keyword |
| twilio.Studio.FlowStepEvent.name | Name of Step from Event | keyword |
| twilio.Studio.FlowStepEvent.parent_step_sid | Parent Step SID from Event | keyword |
| twilio.Studio.FlowStepEvent.step_sid | Step SID from Event | keyword |
| twilio.Studio.FlowStepEvent.transitioned_from | Step that the event transitioned from | keyword |
| twilio.Studio.FlowStepEvent.transitioned_to | Step that the event transitioned to | keyword |
| twilio.SuperSim.ConnectionEvent.account_sid | Account Sid of the SuperSIM this record belongs to. | keyword |
| twilio.SuperSim.ConnectionEvent.apn | Access Point Name used to establish a data session. | keyword |
| twilio.SuperSim.ConnectionEvent.data_download | The amount of data downloaded to the device in bytes between the data_session_update_start_time and data_session_update_end_time. | integer |
| twilio.SuperSim.ConnectionEvent.data_modifier | Indicates if the SuperSIM's data is blocked due to the system such as when the SIM has reached its data limit. | keyword |
| twilio.SuperSim.ConnectionEvent.data_session_data_download | Total number of bytes downloaded over the duration of the data session. Cumulative amount of data_download for all events for this data session so far. | integer |
| twilio.SuperSim.ConnectionEvent.data_session_data_total | Total number of bytes uploaded or downloaded over the duration of the data session | integer |
| twilio.SuperSim.ConnectionEvent.data_session_data_upload | Total number of bytes uploaded over the duration of the data session. Cumulative amount of data_upload for all events for this data session so far. | integer |
| twilio.SuperSim.ConnectionEvent.data_session_end_time | Data Session end time in UTC and in ISO8601 format. | keyword |
| twilio.SuperSim.ConnectionEvent.data_session_sid | Data Session Sid only associated with DataSession events. | keyword |
| twilio.SuperSim.ConnectionEvent.data_session_start_time | Data Session start time in UTC and in ISO8601 format. | keyword |
| twilio.SuperSim.ConnectionEvent.data_session_update_end_time | Data Session update end time in UTC and in ISO8601 format. | keyword |
| twilio.SuperSim.ConnectionEvent.data_session_update_start_time | Data Session update start time in UTC and in ISO8601 format. | keyword |
| twilio.SuperSim.ConnectionEvent.data_total | The amount of data downloaded to the device or uploaded from the device in bytes between the data_session_update_start_time and data_session_update_end_time. | integer |
| twilio.SuperSim.ConnectionEvent.data_upload | The amount of data uploaded from the device in bytes between the data_session_update_start_time and data_session_update_end_time. | integer |
| twilio.SuperSim.ConnectionEvent.error | Object containing information about an error encountered. | object |
| twilio.SuperSim.ConnectionEvent.event_sid | Sid of the event. This is a copy of ce_id header field. | keyword |
| twilio.SuperSim.ConnectionEvent.event_type | Type of connection event. This is a copy of ce_type header field. | keyword |
| twilio.SuperSim.ConnectionEvent.fleet_sid | The SID of the Fleet to which the Super SIM is assigned. | keyword |
| twilio.SuperSim.ConnectionEvent.imei | The 'international mobile equipment identity' is the unique ID of the device using the SIM to connect. May be null as it is not guaranteed that the visited network will pass on this information. | keyword |
| twilio.SuperSim.ConnectionEvent.imsi | The IMSI used by the Super SIM to connect. | keyword |
| twilio.SuperSim.ConnectionEvent.ip_address | The IP address assigned to the device. This IP address is not publicly addressable. | keyword |
| twilio.SuperSim.ConnectionEvent.location | An object containing information about the location of the cell to which the device was connected.  May be null as location information is not guaranteed to be sent by the visited network. | object |
| twilio.SuperSim.ConnectionEvent.network | An object containing information about the network that the Super SIM attempted to connect to or is connected to. | object |
| twilio.SuperSim.ConnectionEvent.rat_type | The generation of wireless technology that the device was using. | keyword |
| twilio.SuperSim.ConnectionEvent.sim_iccid | ICCID of the SuperSIM this record belongs to. | keyword |
| twilio.SuperSim.ConnectionEvent.sim_sid | Sim Sid of the SuperSIM this record belongs to. | keyword |
| twilio.SuperSim.ConnectionEvent.sim_unique_name | Unique name of the SuperSIM this record belongs to. | keyword |
| twilio.SuperSim.ConnectionEvent.timestamp | UTC timestamp when the event occurred in ISO8601 format. | date |
| twilio.TaskRouter.WDSEvent.account_friendly_name | Account friendly name | keyword |
| twilio.TaskRouter.WDSEvent.account_sid | Account SID | keyword |
| twilio.TaskRouter.WDSEvent.group | Group | keyword |
| twilio.TaskRouter.WDSEvent.level | Level | keyword |
| twilio.TaskRouter.WDSEvent.name | name | keyword |
| twilio.TaskRouter.WDSEvent.parent_account_sid | Parent account SID | keyword |
| twilio.TaskRouter.WDSEvent.parent_friendly_name | Parent account friendly name | keyword |
| twilio.TaskRouter.WDSEvent.payload.account_sid | Account SID | keyword |
| twilio.TaskRouter.WDSEvent.payload.event_description | Event description | keyword |
| twilio.TaskRouter.WDSEvent.payload.eventtype | Event type | keyword |
| twilio.TaskRouter.WDSEvent.payload.previous_task_priority | Previous task priority | integer |
| twilio.TaskRouter.WDSEvent.payload.previous_task_queue_name | Previous task queue name | keyword |
| twilio.TaskRouter.WDSEvent.payload.previous_task_queue_sid | Previous task queue SID | keyword |
| twilio.TaskRouter.WDSEvent.payload.reason | Reason | keyword |
| twilio.TaskRouter.WDSEvent.payload.reservation_reason_code | Reservation reason code | integer |
| twilio.TaskRouter.WDSEvent.payload.reservation_sid | Reservation SID | keyword |
| twilio.TaskRouter.WDSEvent.payload.reservation_version | Reservation version | integer |
| twilio.TaskRouter.WDSEvent.payload.resource_sid | Resource SID | keyword |
| twilio.TaskRouter.WDSEvent.payload.resource_type | Resource type | keyword |
| twilio.TaskRouter.WDSEvent.payload.sid | SID | keyword |
| twilio.TaskRouter.WDSEvent.payload.target_changed_reason | Target changed reason | keyword |
| twilio.TaskRouter.WDSEvent.payload.task_age | Task age | integer |
| twilio.TaskRouter.WDSEvent.payload.task_age_in_queue | Task age in queue | integer |
| twilio.TaskRouter.WDSEvent.payload.task_assignment_status | Task assignment status | keyword |
| twilio.TaskRouter.WDSEvent.payload.task_attributes | Task attributes | keyword |
| twilio.TaskRouter.WDSEvent.payload.task_canceled_reason | Task canceled reason | keyword |
| twilio.TaskRouter.WDSEvent.payload.task_channel_sid | Task channel SID | keyword |
| twilio.TaskRouter.WDSEvent.payload.task_channel_unique_name | Task Channel unique name | keyword |
| twilio.TaskRouter.WDSEvent.payload.task_completed_reason | Task completed reason | keyword |
| twilio.TaskRouter.WDSEvent.payload.task_date_created | Task date created | keyword |
| twilio.TaskRouter.WDSEvent.payload.task_priority | Task Priority | integer |
| twilio.TaskRouter.WDSEvent.payload.task_queue_entered_date | Task queue entered date | keyword |
| twilio.TaskRouter.WDSEvent.payload.task_queue_name | Task queue name | keyword |
| twilio.TaskRouter.WDSEvent.payload.task_queue_sid | Task queue SID | keyword |
| twilio.TaskRouter.WDSEvent.payload.task_queue_target_expression | Task queue target expression | keyword |
| twilio.TaskRouter.WDSEvent.payload.task_re_evaluated_reason | Task reevaluated reason | keyword |
| twilio.TaskRouter.WDSEvent.payload.task_routing_target | Task routing target | keyword |
| twilio.TaskRouter.WDSEvent.payload.task_sid | Task SID | keyword |
| twilio.TaskRouter.WDSEvent.payload.task_transfer_sid | Task transfer SID | keyword |
| twilio.TaskRouter.WDSEvent.payload.task_version | Task version | integer |
| twilio.TaskRouter.WDSEvent.payload.timestamp | Timestamp | date |
| twilio.TaskRouter.WDSEvent.payload.transfer_failed_reason | Transfer failed reason | keyword |
| twilio.TaskRouter.WDSEvent.payload.transfer_initiating_reservation_sid | Transfer initiating reservation SID | keyword |
| twilio.TaskRouter.WDSEvent.payload.transfer_initiating_worker_sid | Transfer initiating worker SID | keyword |
| twilio.TaskRouter.WDSEvent.payload.transfer_mode | Transfer mode | keyword |
| twilio.TaskRouter.WDSEvent.payload.transfer_started | Transfer started | keyword |
| twilio.TaskRouter.WDSEvent.payload.transfer_status | Transfer status | keyword |
| twilio.TaskRouter.WDSEvent.payload.transfer_to | Transfer to | keyword |
| twilio.TaskRouter.WDSEvent.payload.transfer_type | Transfer type | keyword |
| twilio.TaskRouter.WDSEvent.payload.worker_activity_name | Worker activity name | keyword |
| twilio.TaskRouter.WDSEvent.payload.worker_activity_sid | Worker activity SID | keyword |
| twilio.TaskRouter.WDSEvent.payload.worker_attributes | Worker attributes | keyword |
| twilio.TaskRouter.WDSEvent.payload.worker_channel_available | Worker channel available | integer |
| twilio.TaskRouter.WDSEvent.payload.worker_channel_available_capacity | Worker channel available capacity | integer |
| twilio.TaskRouter.WDSEvent.payload.worker_channel_capacity | Worker channel capacity | integer |
| twilio.TaskRouter.WDSEvent.payload.worker_channel_previous_capacity | Worker channel previous capacity | integer |
| twilio.TaskRouter.WDSEvent.payload.worker_channel_task_count | Worker channel task count | integer |
| twilio.TaskRouter.WDSEvent.payload.worker_name | Worker name | keyword |
| twilio.TaskRouter.WDSEvent.payload.worker_previous_activity_name | Worker previous activity name | keyword |
| twilio.TaskRouter.WDSEvent.payload.worker_previous_activity_sid | Worker previous activity SID | keyword |
| twilio.TaskRouter.WDSEvent.payload.worker_sid | Worker SID | keyword |
| twilio.TaskRouter.WDSEvent.payload.worker_time_in_previous_activity | Worker time in previous activity in seconds | integer |
| twilio.TaskRouter.WDSEvent.payload.worker_time_in_previous_activity_ms | Worker time in previous activity in millis | integer |
| twilio.TaskRouter.WDSEvent.payload.workflow_filter_expression | Workflow filter expression | keyword |
| twilio.TaskRouter.WDSEvent.payload.workflow_filter_name | Workflow filter name | keyword |
| twilio.TaskRouter.WDSEvent.payload.workflow_filter_target_expression | Workflow filter target expression | keyword |
| twilio.TaskRouter.WDSEvent.payload.workflow_filter_target_name | Workflow filter name | keyword |
| twilio.TaskRouter.WDSEvent.payload.workflow_name | Workflow name | keyword |
| twilio.TaskRouter.WDSEvent.payload.workflow_sid | Workflow SID | keyword |
| twilio.TaskRouter.WDSEvent.payload.workspace_name | Worspace name | keyword |
| twilio.TaskRouter.WDSEvent.payload.workspace_sid | Workspace SID | keyword |
| twilio.TaskRouter.WDSEvent.payload_type | Payload type | keyword |
| twilio.TaskRouter.WDSEvent.product_name | Product name | keyword |
| twilio.TaskRouter.WDSEvent.publisher | Publisher | keyword |
| twilio.TaskRouter.WDSEvent.publisher_metadata | Publisher metadata | keyword |
| twilio.TaskRouter.WDSEvent.sid | SID | keyword |
| twilio.TaskRouter.WDSEvent.timestamp | Timestamp | date |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.account_sid | Account SID associated with the room | keyword |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.call_sid | https://www.twilio.com/docs/video/video-log-analyzer/video-log-analyzer-api | keyword |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.codecs | Codecs detected from the participant. Can be VP8, H264, or VP9. | keyword |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.duration_sec | Amount of time in seconds the participant was in the room | integer |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.edge_location | Name of the edge location the participant connected to. | keyword |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.end_reason | Reason the participant left the room. | keyword |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.error_code | Errors encountered by the participant. | integer |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.error_code_url | Twilio error code dictionary link. | keyword |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.is_adhoc | https://www.twilio.com/docs/video/video-log-analyzer/video-log-analyzer-api | boolean |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.join_time | When the participant joined the room | date |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.leave_time | When the participant left the room | date |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.media_region | Twilio media region the participant connected to. | keyword |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.num_audio_tracks | https://www.twilio.com/docs/video/video-log-analyzer/video-log-analyzer-api | integer |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.num_data_tracks | https://www.twilio.com/docs/video/video-log-analyzer/video-log-analyzer-api | integer |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.num_video_tracks | https://www.twilio.com/docs/video/video-log-analyzer/video-log-analyzer-api | integer |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.participant_identity | The application-defined string that uniquely identifies the participant within a Room | keyword |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.participant_sid | Unique identifier for the participant | keyword |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.properties.is_adhoc | Indicates if the participant joined the room ad-hoc. | boolean |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.properties.num_audio_tracks | Number of audio tracks from the participant. | integer |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.properties.num_data_tracks | Number of data tracks from the participant. | integer |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.properties.num_video_tracks | Number of video tracks from the participant. | integer |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.properties.record_on_connect | Indicates if the participant was recorded as soon as they joined the room. | boolean |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.publisher_info.browser_major | https://www.twilio.com/docs/video/video-log-analyzer/video-log-analyzer-api | keyword |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.publisher_info.browser_name | https://www.twilio.com/docs/video/video-log-analyzer/video-log-analyzer-api | keyword |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.publisher_info.browser_version | https://www.twilio.com/docs/video/video-log-analyzer/video-log-analyzer-api | keyword |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.publisher_info.device_architecture | https://www.twilio.com/docs/video/video-log-analyzer/video-log-analyzer-api | keyword |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.publisher_info.device_manufacturer | https://www.twilio.com/docs/video/video-log-analyzer/video-log-analyzer-api | keyword |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.publisher_info.device_model | https://www.twilio.com/docs/video/video-log-analyzer/video-log-analyzer-api | keyword |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.publisher_info.name | SDK type; e.g., twilio-video-js | keyword |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.publisher_info.platform_name | https://www.twilio.com/docs/video/video-log-analyzer/video-log-analyzer-api | keyword |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.publisher_info.platform_version | https://www.twilio.com/docs/video/video-log-analyzer/video-log-analyzer-api | keyword |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.publisher_info.sdk_version | SDK version | keyword |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.record_on_connect | https://www.twilio.com/docs/video/video-log-analyzer/video-log-analyzer-api | boolean |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.recording_duration_sec | https://www.twilio.com/docs/video/video-log-analyzer/video-log-analyzer-api | integer |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.room_sid | Unique identifier for the room | keyword |
| twilio.VideoInsights.VideoLogAnalyzerParticipantSummary.status | Status of the room. Can be in_progress or completed. | keyword |
| twilio.VideoInsights.VideoLogAnalyzerRoomSummary.account_sid | Account SID associated with this room | keyword |
| twilio.VideoInsights.VideoLogAnalyzerRoomSummary.codecs | Codecs used by participants in the room. Can be VP8, H264, or VP9 | keyword |
| twilio.VideoInsights.VideoLogAnalyzerRoomSummary.concurrent_participants | Actual number of concurrent participants | integer |
| twilio.VideoInsights.VideoLogAnalyzerRoomSummary.create_time | Creation time of the room | date |
| twilio.VideoInsights.VideoLogAnalyzerRoomSummary.created_method | How the room was created. Can be sdk, ad_hoc, or api | keyword |
| twilio.VideoInsights.VideoLogAnalyzerRoomSummary.duration_sec | Total room duration from create time to end time | integer |
| twilio.VideoInsights.VideoLogAnalyzerRoomSummary.edge_location | Edge location of Twilio media servers for the room | keyword |
| twilio.VideoInsights.VideoLogAnalyzerRoomSummary.end_reason | Reason the room ended. Can be room_ended_via_api or timeout | keyword |
| twilio.VideoInsights.VideoLogAnalyzerRoomSummary.end_time | End time for the room | date |
| twilio.VideoInsights.VideoLogAnalyzerRoomSummary.max_concurrent_participants | Maximum number of participants allowed in the room at the same time allowed by the application settings | integer |
| twilio.VideoInsights.VideoLogAnalyzerRoomSummary.max_participants | Max number of total participants allowed by the application settings | integer |
| twilio.VideoInsights.VideoLogAnalyzerRoomSummary.media_region | Region of Twilio media servers for the room | keyword |
| twilio.VideoInsights.VideoLogAnalyzerRoomSummary.processing_state | Video Log Analyzer resource state | keyword |
| twilio.VideoInsights.VideoLogAnalyzerRoomSummary.recording_enabled | Boolean indicating if recording is enabled for the room | boolean |
| twilio.VideoInsights.VideoLogAnalyzerRoomSummary.room_name | Room friendly name | keyword |
| twilio.VideoInsights.VideoLogAnalyzerRoomSummary.room_region | https://www.twilio.com/docs/video/video-log-analyzer/video-log-analyzer-api | keyword |
| twilio.VideoInsights.VideoLogAnalyzerRoomSummary.room_sid | Unique identifier for the room | keyword |
| twilio.VideoInsights.VideoLogAnalyzerRoomSummary.room_status | Status of the room. Can be in_progress or completed | keyword |
| twilio.VideoInsights.VideoLogAnalyzerRoomSummary.room_type | Type of room. Can be go, peer_to_peer, group, or group_small | keyword |
| twilio.VideoInsights.VideoLogAnalyzerRoomSummary.status_callback | Webhook provided for status callbacks | keyword |
| twilio.VideoInsights.VideoLogAnalyzerRoomSummary.status_callback_method | HTTP method provided for status callback URL | keyword |
| twilio.VideoInsights.VideoLogAnalyzerRoomSummary.total_participant_duration_sec | Combined amount of participant time in the room | integer |
| twilio.VideoInsights.VideoLogAnalyzerRoomSummary.total_recording_duration_sec | Combined amount of recorded seconds for participants in the room | integer |
| twilio.VideoInsights.VideoLogAnalyzerRoomSummary.unique_participant_identities | Unique number of participant identities | integer |
| twilio.VideoInsights.VideoLogAnalyzerRoomSummary.unique_participants | Number of participants. May include duplicate identities for participants who left and rejoined | integer |
| twilio.VoiceInsights.CallEvent.account_sid | The account SID this call belongs to | keyword |
| twilio.VoiceInsights.CallEvent.call_sid | Call SID for the call the events are associated with | keyword |
| twilio.VoiceInsights.CallEvent.carrier_edge | Represents the connection between Twilio and our immediate carrier partners. The events here describe the call lifecycle as reported by Twilio's carrier media gateways | object |
| twilio.VoiceInsights.CallEvent.client_edge | Represents the Twilio media gateway for Client calls. The events here describe the call lifecycle as reported by Twilio's Voice SDK media gateways | object |
| twilio.VoiceInsights.CallEvent.edge | The edge reporting the event | keyword |
| twilio.VoiceInsights.CallEvent.group | Event group | keyword |
| twilio.VoiceInsights.CallEvent.level | Detail level | keyword |
| twilio.VoiceInsights.CallEvent.name | Event name | keyword |
| twilio.VoiceInsights.CallEvent.sdk_edge | Represents the Voice SDK running locally in the browser or in the Android/iOS application. The events here are emitted by the Voice SDK in response to certain call progress events, network changes, or call quality conditions | object |
| twilio.VoiceInsights.CallEvent.sip_edge | Represents the Twilio media gateway for SIP interface and SIP trunking calls. The events here describe the call lifecycle as reported by Twilio's public media gateways | object |
| twilio.VoiceInsights.CallEvent.timestamp | Event time | date |
| twilio.VoiceInsights.CallSummary.account_sid | The account SID this call belongs to | keyword |
| twilio.VoiceInsights.CallSummary.attributes | Contains call-flow specific details | object |
| twilio.VoiceInsights.CallSummary.call_sid | SID for the call | keyword |
| twilio.VoiceInsights.CallSummary.call_state | Status of the call | keyword |
| twilio.VoiceInsights.CallSummary.call_type | Describes the call type; client, carrier, sip, trunking | keyword |
| twilio.VoiceInsights.CallSummary.carrier_edge | Contains metrics and properties for the Twilio media gateway of a PSTN call | object |
| twilio.VoiceInsights.CallSummary.client_edge | Contains metrics and properties for the Twilio media gateway of a Client call | object |
| twilio.VoiceInsights.CallSummary.connect_duration | Duration between when the call was answered and when it ended | integer |
| twilio.VoiceInsights.CallSummary.created_time | Time the call resource was created. Can be different from start_time in the event of queueing due to CPS. | date |
| twilio.VoiceInsights.CallSummary.duration | Duration between when the call was initiated and the call was ended | integer |
| twilio.VoiceInsights.CallSummary.end_time | Call end time | date |
| twilio.VoiceInsights.CallSummary.from.callee | Dialed destination | keyword |
| twilio.VoiceInsights.CallSummary.from.caller | Caller ID of calling party | keyword |
| twilio.VoiceInsights.CallSummary.from.carrier | Serving carrier of destination | keyword |
| twilio.VoiceInsights.CallSummary.from.city | City name based on lat/long or IP address | keyword |
| twilio.VoiceInsights.CallSummary.from.connection | Landline, mobile, voip | keyword |
| twilio.VoiceInsights.CallSummary.from.country_code | Two-letter ISO country code | keyword |
| twilio.VoiceInsights.CallSummary.from.country_subdivision | Additional location details; e.g. California | keyword |
| twilio.VoiceInsights.CallSummary.from.ip_address | Public IP of Client user | keyword |
| twilio.VoiceInsights.CallSummary.from.location | Lat/long for number prefix | object |
| twilio.VoiceInsights.CallSummary.from.number_prefix | E.164 country code + three digits | keyword |
| twilio.VoiceInsights.CallSummary.from.sdk | undefined | object |
| twilio.VoiceInsights.CallSummary.parent_account_sid | Parent account SID for calls placed using subaccounts | keyword |
| twilio.VoiceInsights.CallSummary.parent_call_sid | Parent call SID for calls | keyword |
| twilio.VoiceInsights.CallSummary.processing_state | Represents the summarization state of the resource | keyword |
| twilio.VoiceInsights.CallSummary.processing_version | Increments as updates to the summary are made while processing_state is partial | integer |
| twilio.VoiceInsights.CallSummary.properties.direction | The direction of the call; inbound, outbound-api, outbound-dial, trunking-originating, trunking-terminating | keyword |
| twilio.VoiceInsights.CallSummary.properties.disconnected_by | Direction of the SIP BYE received at Twilio signaling gateway. | keyword |
| twilio.VoiceInsights.CallSummary.properties.last_sip_response_num | The numeric value of the last SIP response received for the call | integer |
| twilio.VoiceInsights.CallSummary.properties.pdd_ms | Post-dial delay in milliseconds | integer |
| twilio.VoiceInsights.CallSummary.properties.queue_time | Estimated time in milliseconds between when a Programmable Voice call is created and when the call actually begins. | integer |
| twilio.VoiceInsights.CallSummary.sdk_edge | Contains metrics and properties for the SDK sensor library for Client calls | object |
| twilio.VoiceInsights.CallSummary.sip_edge | Contains metrics and properties for the Twilio media gateway of a SIP Interface or Trunking call | object |
| twilio.VoiceInsights.CallSummary.start_time | Call start time | date |
| twilio.VoiceInsights.CallSummary.tags | Tags applied to calls by Voice Insights analysis indicating a condition that could result in subjective degradation of the call quality | keyword |
| twilio.VoiceInsights.CallSummary.to.callee | Dialed destination | keyword |
| twilio.VoiceInsights.CallSummary.to.caller | Caller ID of calling party | keyword |
| twilio.VoiceInsights.CallSummary.to.carrier | Serving carrier of destination | keyword |
| twilio.VoiceInsights.CallSummary.to.city | City name based on lat/long or IP address | keyword |
| twilio.VoiceInsights.CallSummary.to.connection | Landline, mobile, voip | keyword |
| twilio.VoiceInsights.CallSummary.to.country_code | Two-letter ISO country code | keyword |
| twilio.VoiceInsights.CallSummary.to.country_subdivision | Additional location details; e.g. California | keyword |
| twilio.VoiceInsights.CallSummary.to.ip_address | Public IP of Client user | keyword |
| twilio.VoiceInsights.CallSummary.to.location | Lat/long for number prefix | object |
| twilio.VoiceInsights.CallSummary.to.number_prefix | E.164 country code + three digits | keyword |
| twilio.VoiceInsights.CallSummary.to.sdk | undefined | object |
| twilio.VoiceInsights.CallSummary.trust.branded_call.brand_sid | Brand SID | keyword |
| twilio.VoiceInsights.CallSummary.trust.branded_call.branded | Indicates if branding details were successfully displayed on the destination device | boolean |
| twilio.VoiceInsights.CallSummary.trust.branded_call.branded_channel_sid | Branded channel SID | keyword |
| twilio.VoiceInsights.CallSummary.trust.branded_call.caller | Caller ID provided | keyword |
| twilio.VoiceInsights.CallSummary.trust.branded_call.use_case | Use case for the call | keyword |
| twilio.VoiceInsights.CallSummary.trust.verified_caller.verified | Indicates if the caller ID provided has been verified; e.g. SHAKEN/STIR A attestation | boolean |
| twilio.VoiceInsights.ConferenceParticipantSummary.account_sid | The unique SID identifier of the account. | keyword |
| twilio.VoiceInsights.ConferenceParticipantSummary.agent_audio | The value of agent_audio | boolean |
| twilio.VoiceInsights.ConferenceParticipantSummary.call_direction | Direction of media flow from the perspective of the edge. Inbound or outbound | keyword |
| twilio.VoiceInsights.ConferenceParticipantSummary.call_sid | The unique SID identifier of the Call. | keyword |
| twilio.VoiceInsights.ConferenceParticipantSummary.call_state | Status of the call; completed, failed, etc. | keyword |
| twilio.VoiceInsights.ConferenceParticipantSummary.call_status | Staus of the call | keyword |
| twilio.VoiceInsights.ConferenceParticipantSummary.call_type | Type of call | keyword |
| twilio.VoiceInsights.ConferenceParticipantSummary.coached_participants | Call sids coached by the participant | keyword |
| twilio.VoiceInsights.ConferenceParticipantSummary.conference_region | Region of the conference mixed. | keyword |
| twilio.VoiceInsights.ConferenceParticipantSummary.conference_sid | The unique SID identifier of the Conference. | keyword |
| twilio.VoiceInsights.ConferenceParticipantSummary.country_code | Country Code of Participant | keyword |
| twilio.VoiceInsights.ConferenceParticipantSummary.duration_seconds | Participant duration in seconds. | integer |
| twilio.VoiceInsights.ConferenceParticipantSummary.events.coaching | Unix timestamps when paticipant is coaching. | date |
| twilio.VoiceInsights.ConferenceParticipantSummary.events.coaching_stopped | Unix timestamp when paticipant stop coaching. | date |
| twilio.VoiceInsights.ConferenceParticipantSummary.events.hold | Unix timestamps when participant is on hold | date |
| twilio.VoiceInsights.ConferenceParticipantSummary.events.modify_beep | Unix timestamps when modify beep action occurs. | date |
| twilio.VoiceInsights.ConferenceParticipantSummary.events.modify_coached_participant | Unix timestamp when paticipant changed the participant to coach. | date |
| twilio.VoiceInsights.ConferenceParticipantSummary.events.modify_exit | Unix timestamps when modify exit action occurs. | date |
| twilio.VoiceInsights.ConferenceParticipantSummary.events.mute | Unix timestamps when participant is on mute | date |
| twilio.VoiceInsights.ConferenceParticipantSummary.events.unhold | Unix timestamps when participant is on uhold | date |
| twilio.VoiceInsights.ConferenceParticipantSummary.events.unmute | Unix timestamps when participant is unmuted. | date |
| twilio.VoiceInsights.ConferenceParticipantSummary.from | Call source. | keyword |
| twilio.VoiceInsights.ConferenceParticipantSummary.is_coach | Is participant a coach | boolean |
| twilio.VoiceInsights.ConferenceParticipantSummary.is_moderator | Is participant a moderator. | boolean |
| twilio.VoiceInsights.ConferenceParticipantSummary.jitter_buffer_size | Jitter buffer size for the connecting participant. | keyword |
| twilio.VoiceInsights.ConferenceParticipantSummary.join_time | ISO format time participant joined. | date |
| twilio.VoiceInsights.ConferenceParticipantSummary.label | Custom label for the participant resource, up to 64 characters. | keyword |
| twilio.VoiceInsights.ConferenceParticipantSummary.leave_time | ISO format time participant left. | date |
| twilio.VoiceInsights.ConferenceParticipantSummary.metrics | undefined | object |
| twilio.VoiceInsights.ConferenceParticipantSummary.outbound_queue_length | Call position in the queue | integer |
| twilio.VoiceInsights.ConferenceParticipantSummary.outbound_time_in_queue | Time spent in queue before joining the conference | integer |
| twilio.VoiceInsights.ConferenceParticipantSummary.participant_region | Region of the participant conference mixed | keyword |
| twilio.VoiceInsights.ConferenceParticipantSummary.participant_sid | The unique SID identifier of the participant. | keyword |
| twilio.VoiceInsights.ConferenceParticipantSummary.processing_state | Processing state for the Conference Summary resource. | keyword |
| twilio.VoiceInsights.ConferenceParticipantSummary.properties.beep_on_enter | Boolean value set to allow beep on enter of conference | boolean |
| twilio.VoiceInsights.ConferenceParticipantSummary.properties.beep_on_exit | Boolean value set to allow beep on exist of conference | boolean |
| twilio.VoiceInsights.ConferenceParticipantSummary.properties.end_conference_on_exit | boolean value set to end the conference when the participant leave the conference | boolean |
| twilio.VoiceInsights.ConferenceParticipantSummary.properties.enter_muted | Boolean value set to join participant as muted in the conference. | boolean |
| twilio.VoiceInsights.ConferenceParticipantSummary.properties.play_early_media | boolean value set to allow an agent to hear the state of the outbound call, including ringing or disconnect messages. | boolean |
| twilio.VoiceInsights.ConferenceParticipantSummary.properties.recording_enabled | boolean value set to allow recording of the conference | boolean |
| twilio.VoiceInsights.ConferenceParticipantSummary.properties.requested_region | Request region to mix the conference. | keyword |
| twilio.VoiceInsights.ConferenceParticipantSummary.properties.start_conference_on_enter | Boolean value set to start the conference when the participant joins the conference | boolean |
| twilio.VoiceInsights.ConferenceParticipantSummary.properties.trim_recording | boolean value set to trim leading and trailing silence from your recorded conference audio files. | boolean |
| twilio.VoiceInsights.ConferenceParticipantSummary.quality_issues | Count of issues detected | integer |
| twilio.VoiceInsights.ConferenceParticipantSummary.to | Call destination. | keyword |
| twilio.VoiceInsights.ConferenceParticipantSummary.whisper | The value of whisper | keyword |
| twilio.VoiceInsights.ConferenceSummary.account_sid | The unique SID identifier of the account. | keyword |
| twilio.VoiceInsights.ConferenceSummary.conference_sid | The unique SID identifier of the Conference. | keyword |
| twilio.VoiceInsights.ConferenceSummary.connect_duration_seconds | Duration of the between conference start event and conference end event in seconds. | integer |
| twilio.VoiceInsights.ConferenceSummary.create_time | Conference creation date and time in ISO 8601 format. | date |
| twilio.VoiceInsights.ConferenceSummary.detected_issues.call_quality | The count of issue occured. | integer |
| twilio.VoiceInsights.ConferenceSummary.detected_issues.participant_behavior | The count of issue occured. | integer |
| twilio.VoiceInsights.ConferenceSummary.detected_issues.region_configuration | The count of issue occured. | integer |
| twilio.VoiceInsights.ConferenceSummary.duration_seconds | Conference duration in seconds. | integer |
| twilio.VoiceInsights.ConferenceSummary.end_reason | Conference end reason; e.g. last participant left, modified by API, etc. | keyword |
| twilio.VoiceInsights.ConferenceSummary.end_time | Conference end date and time in ISO 8601 format. | date |
| twilio.VoiceInsights.ConferenceSummary.ended_by | Call SID that ended the conference. | keyword |
| twilio.VoiceInsights.ConferenceSummary.friendly_name | Custom label for the conference resource, up to 64 characters. | keyword |
| twilio.VoiceInsights.ConferenceSummary.max_concurrent_participants | Actual maximum concurrent participants. | integer |
| twilio.VoiceInsights.ConferenceSummary.max_participants | Max participants specified in config. | integer |
| twilio.VoiceInsights.ConferenceSummary.mixer_region | Twilio region where the conference media was mixed. | keyword |
| twilio.VoiceInsights.ConferenceSummary.mixer_region_requested | Twilio region where conference mixed was specified to be mixed in configuration. | keyword |
| twilio.VoiceInsights.ConferenceSummary.processing_state | Processing state for the Conference Summary resource. | keyword |
| twilio.VoiceInsights.ConferenceSummary.recording_enabled | Boolean. Indicates whether recording was enabled. | boolean |
| twilio.VoiceInsights.ConferenceSummary.start_time | Timestamp in ISO 8601 format when the conference started. | date |
| twilio.VoiceInsights.ConferenceSummary.status | Status of this Conference; `in_progress`, `not_started`, `completed` or `summary_timeout`. if Twilio don't receive `last_participant_left` event, summary will be timeout after 24 hours | keyword |
| twilio.VoiceInsights.ConferenceSummary.tag_info | undefined | object |
| twilio.VoiceInsights.ConferenceSummary.tags | Tags for detected conference conditions and participant behaviors. | keyword |
| twilio.VoiceInsights.ConferenceSummary.unique_participants | Unique conference participants based on caller ID. | integer |
| twilio.datacontenttype | Content type of the data in the event | keyword |
| twilio.dataschema | Schema used for the event | keyword |
| twilio.id | Unique identifier of the event | keyword |
| twilio.source | Source of the event | keyword |
| twilio.specversion | CloudEvents specification version used for the event | keyword |
| twilio.time | Date and time at which the event was triggered | date |
| twilio.type | Type of the event | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
