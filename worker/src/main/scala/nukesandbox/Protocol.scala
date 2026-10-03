package nukesandbox

import spray.json.*

final case class AnalyzeCommand(
    eventType: String,
    jobId: String,
    targetUrl: String,
    requestedBy: String,
    requestId: String
)

final case class AnalyzeRequest(targetUrl: String)

final case class JobEvent(
    status: String,
    stage: String,
    result: Option[JsValue] = None,
    error: Option[String] = None
)

object Protocol extends DefaultJsonProtocol {
  given RootJsonFormat[AnalyzeCommand] = new RootJsonFormat[AnalyzeCommand] {
    def write(command: AnalyzeCommand): JsValue =
      JsObject(
        "event_type" -> JsString(command.eventType),
        "job_id" -> JsString(command.jobId),
        "target_url" -> JsString(command.targetUrl),
        "requested_by" -> JsString(command.requestedBy),
        "request_id" -> JsString(command.requestId)
      )

    def read(value: JsValue): AnalyzeCommand =
      value.asJsObject.getFields("event_type", "job_id", "target_url", "requested_by", "request_id") match
        case Seq(JsString(eventType), JsString(jobId), JsString(targetUrl), JsString(requestedBy), JsString(requestId)) =>
          AnalyzeCommand(eventType, jobId, targetUrl, requestedBy, requestId)
        case _ => throw DeserializationException("AnalyzeCommand is missing required fields")
  }

  given RootJsonFormat[AnalyzeRequest] = new RootJsonFormat[AnalyzeRequest] {
    def write(request: AnalyzeRequest): JsValue = JsObject("target_url" -> JsString(request.targetUrl))
    def read(value: JsValue): AnalyzeRequest =
      value.asJsObject.fields.get("target_url") match
        case Some(JsString(targetUrl)) => AnalyzeRequest(targetUrl)
        case _ => throw DeserializationException("AnalyzeRequest.target_url is required")
  }

  given RootJsonFormat[JobEvent] = new RootJsonFormat[JobEvent] {
    def write(event: JobEvent): JsValue =
      JsObject(
        Map(
          "status" -> JsString(event.status),
          "stage" -> JsString(event.stage)
        ) ++ event.result.map("result" -> _) ++ event.error.map(message => "error" -> JsString(message))
      )

    def read(value: JsValue): JobEvent =
      val fields = value.asJsObject.fields
      JobEvent(
        status = fields("status").convertTo[String],
        stage = fields("stage").convertTo[String],
        result = fields.get("result"),
        error = fields.get("error").collect { case JsString(message) => message }
      )
  }

  def parseCommand(json: String): AnalyzeCommand =
    json.parseJson.convertTo[AnalyzeCommand]
}
