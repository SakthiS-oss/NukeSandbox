package nukesandbox

import org.apache.kafka.clients.consumer.ConsumerConfig
import org.apache.kafka.common.serialization.StringDeserializer
import org.apache.pekko.actor.typed.ActorSystem
import org.apache.pekko.actor.typed.scaladsl.adapter.TypedActorSystemOps
import org.apache.pekko.http.scaladsl.Http
import org.apache.pekko.http.scaladsl.model.*
import org.apache.pekko.http.scaladsl.model.headers.RawHeader
import org.apache.pekko.http.scaladsl.unmarshalling.Unmarshal
import org.apache.pekko.kafka.scaladsl.{Committer, Consumer}
import org.apache.pekko.kafka.{CommitterSettings, ConsumerSettings, Subscriptions}
import spray.json.*
import Protocol.given

import scala.concurrent.{ExecutionContext, Future}
import scala.util.control.NonFatal

final class AnalysisStream(system: ActorSystem[?]):
  private given ActorSystem[?] = system
  private given ExecutionContext = system.executionContext
  private val classic = system.toClassic
  private val config = system.settings.config.getConfig("nukesandbox")
  private val bootstrap = config.getString("kafka-bootstrap")
  private val topic = config.getString("command-topic")
  private val groupId = config.getString("consumer-group")
  private val apiBase = config.getString("api-base-url").stripSuffix("/")
  private val token = config.getString("internal-token")
  private val maxInFlight = config.getInt("max-in-flight")

  def run(): Consumer.DrainingControl[?] =
    val consumerSettings = ConsumerSettings(classic, new StringDeserializer, new StringDeserializer)
      .withBootstrapServers(bootstrap)
      .withGroupId(groupId)
      .withProperty(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest")
      .withProperty(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, "false")

    Consumer
      .committableSource(consumerSettings, Subscriptions.topics(topic))
      .mapAsync(maxInFlight) { message =>
        val command = Protocol.parseCommand(message.record.value)
        process(command).map(_ => message.committableOffset)
      }
      .toMat(Committer.sink(CommitterSettings(classic)))(Consumer.DrainingControl.apply)
      .run()

  private def process(command: AnalyzeCommand): Future[Unit] =
    if command.eventType != "AnalyzeRequested" then Future.unit
    else
      (for
        _ <- report(command.jobId, JobEvent("running", "sandbox"))
        result <- execute(command)
        _ <- report(command.jobId, JobEvent("succeeded", "report", result = Some(result)))
      yield ()).recoverWith { case NonFatal(error) =>
        system.log.error("analysis job {} failed: {}", command.jobId, error.getMessage)
        report(command.jobId, JobEvent("failed", "worker", error = Some(error.getMessage))).map(_ => ())
      }

  private def execute(command: AnalyzeCommand): Future[JsValue] =
    val request = HttpRequest(
      method = HttpMethods.POST,
      uri = s"$apiBase/internal/execute",
      headers = Seq(RawHeader("X-Internal-Token", token), RawHeader("X-Request-ID", command.requestId)),
      entity = HttpEntity(ContentTypes.`application/json`, AnalyzeRequest(command.targetUrl).toJson.compactPrint)
    )
    Http(classic).singleRequest(request).flatMap { response =>
      Unmarshal(response.entity).to[String].map { body =>
        if response.status.isSuccess then body.parseJson
        else throw RuntimeException(s"sandbox executor returned ${response.status}: $body")
      }
    }

  private def report(jobId: String, event: JobEvent): Future[Unit] =
    val request = HttpRequest(
      method = HttpMethods.POST,
      uri = s"$apiBase/internal/jobs/$jobId/events",
      headers = Seq(RawHeader("X-Internal-Token", token)),
      entity = HttpEntity(ContentTypes.`application/json`, event.toJson.compactPrint)
    )
    Http(classic).singleRequest(request).flatMap { response =>
      response.discardEntityBytes()
      if response.status.isSuccess then Future.unit
      else Future.failed(RuntimeException(s"job event ${response.status}"))
    }
