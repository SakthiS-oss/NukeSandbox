package nukesandbox

import org.apache.pekko.actor.typed.ActorSystem
import org.apache.pekko.actor.typed.scaladsl.Behaviors
import org.apache.pekko.actor.typed.scaladsl.adapter.TypedActorSystemOps

import scala.concurrent.Await
import scala.concurrent.duration.Duration

object WorkerApp:
  def main(args: Array[String]): Unit =
    val system = ActorSystem(Behaviors.empty, "nukesandbox-worker")
    system.log.info("starting Pekko analysis worker")
    val control = AnalysisStream(system).run()
    sys.addShutdownHook {
      Await.result(control.drainAndShutdown(system.toClassic), Duration.Inf)
      system.terminate()
    }
    Await.result(system.whenTerminated, Duration.Inf)
