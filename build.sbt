ThisBuild / version := "0.1.0-SNAPSHOT"

ThisBuild / scalaVersion := "3.2.2"

lazy val root = (project in file("."))
  .settings(
    name := "CT5059---Email-Scanner---Scala",
    idePackagePrefix := Some("lat.jack.emailscanner")
  )
