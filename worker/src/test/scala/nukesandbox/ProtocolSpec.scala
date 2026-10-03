package nukesandbox

import org.scalatest.funsuite.AnyFunSuite
import spray.json.*

class ProtocolSpec extends AnyFunSuite:
  test("parses an AnalyzeRequested command without treating the URL as a shell string") {
    val json =
      """{"event_type":"AnalyzeRequested","job_id":"job-1","target_url":"https://example.com; touch /tmp/pwned","requested_by":"alice","request_id":"req-1"}"""
    val command = Protocol.parseCommand(json)
    assert(command.eventType == "AnalyzeRequested")
    assert(command.jobId == "job-1")
    assert(command.targetUrl == "https://example.com; touch /tmp/pwned")
  }

  test("job events serialize the fields the Python API expects") {
    val json = JobEvent("succeeded", "report", result = Some("""{"target_url":"https://example.com"}""".parseJson)).toJson.asJsObject
    assert(json.fields("status") == JsString("succeeded"))
    assert(json.fields("stage") == JsString("report"))
    assert(json.fields.contains("result"))
  }
