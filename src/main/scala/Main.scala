package lat.jack.emailscanner

import java.io.File
import scala.collection.MapView
import scala.collection.immutable.HashMap
import scala.io.Source

object Main {
  private val illegalPhrases: List[String] = List("threat", "vulnerabilities", "attack", "loopholes", "whitelist", "blacklist", "hash", "encryption")
  private val minimumIllegalPhraseCount: Int = 5

  private class Report(val email: String, val illegalPhrases: Seq[(String, Int)], val illegalPhraseCount: Int, val wordOccurrences: Seq[(String, Int)], val suspicious: Boolean)

  private def readFile(fileName: String): String = {
    val file = Source.fromFile(fileName)
    val fileContents = file.mkString
    file.close()
    fileContents
  }

  private def readDirectory(directoryPath: String): Array[String] = {
    val directory = new File(directoryPath)
    if (directory.exists && directory.isDirectory) {
      directory.listFiles.filter(_.isFile).map(_.getName)
    } else {
      Array[String]()
    }
  }

  def main(args: Array[String]): Unit = {

    if (args.length == 0) { // No params
      println("No parameters have been passed in. Please pass in either -F or -D")
      println("For more information, please run the program with the -H parameter")

    } else if (args.length == 1) { // Help
      if (args(0) == "-H") {
        println("This program will scan an email for suspicious phrases")
        println("To run the program, please pass in either -F or -D")
        println("-F will scan a single file")
        println("-D will scan all the files in a directory")

      } else { // Invalid param
        println("Please pass in either -F or -D")
        println("For more information, please run the program with the -H parameter")
      }

    } else if (args.length == 2) {
      if (args(0) == "-F") { // Read a single file
        val fileContents = readFile(args(1))
        val report = scanEmail(fileContents)
        analyseReport(report)

      } else if (args(0) == "-D") { // Read a whole directory
        val files = readDirectory(args(1))

        val reports: List[Report] = files.map(file => {
          val fileContents = readFile(args(1) + "/" + file)
          scanEmail(fileContents)
        }).toList

        analyseReports(reports)

      } else {
        println("Please pass in either -F or -D")
        println("For more information, please run the program with the -H parameter")
      }
    } else {
      println("Please pass in either -F or -D")
      println("For more information, please run the program with the -H parameter")
    }
  }

  private def analyseReport(report: Report): Unit = {

    var build = ""
    var i = 0

    for (illegalPhrase <- report.illegalPhrases) {
      build += illegalPhrase._1 + s" (${illegalPhrase._2})"

      if (i < report.illegalPhrases.length - 1) {
        build += ", "
      } else build += "."
      i += 1
    }

    println(s"Email: '${report.email}'")
    println("")
    println(s"Total Illegal Phrases Used: ${report.illegalPhraseCount}")
    println(s"Illegal Phrases used '${build}'")
    println("")

    if (report.wordOccurrences.length > 5 && report.illegalPhraseCount >= minimumIllegalPhraseCount) {
      println("This is a Suspicious File")
    } else {
      println("This file is Benign")
    }

  }

  private def analyseReports(reports: List[Report]): Unit = {

    if (reports.isEmpty) {
      println("Error, No reports were generated.")
      return
    }

    val totalIllegalPhrasesUsed: Int = reports.map(_.illegalPhraseCount).sum
    val mostCommonIllegalPhrase: String = reports.flatMap(_.illegalPhrases).groupBy(_._1).mapValues(_.map(_._2).sum).maxBy(_._2)._1
    val leastCommonIllegalPhrase: String = reports.flatMap(_.illegalPhrases).groupBy(_._1).mapValues(_.map(_._2).sum).minBy(_._2)._1
    val averageIllegalPhrasesUsed: Double = totalIllegalPhrasesUsed.toDouble / reports.length.toDouble
    val totalSuspicious: Int = reports.count(_.suspicious)

    println(s"Folder Email Report Summary")
    println(s"")
    println(s"Total Emails Scanned: ${reports.length}")
    println(s"Total Suspicious Files: ${totalSuspicious}/${reports.length}")
    println(s"")
    println(s"Total Illegal Phrases Found: ${totalIllegalPhrasesUsed}")
    println(s"Average Illegal Phrases (across all emails): ${averageIllegalPhrasesUsed}")
    println(s"")
    println(s"Most Common Illegal Phrase: ${mostCommonIllegalPhrase}")
    println(s"Least Common Illegal Phrase: ${leastCommonIllegalPhrase}")

  }

  private def scanEmail(emailInput: String): Report = {
    var email: String = emailInput

    email = email.toLowerCase() // Normalize the string - to lowercase

    email = email // Replace characters which contain accents with their non-accented equivalent
      .replaceAll("[áàâãåä]", "a")
      .replaceAll("[éèêë]", "e")
      .replaceAll("[íìîï]", "i")
      .replaceAll("[óòôõö]", "o")
      .replaceAll("[úùûü]", "u")
      .replaceAll("ç", "c")

    val emailInputWords: Array[String] = email.split("\\W+") // Split each word into a string (also on punctuation etc)

    val wordOccurrences: Seq[(String, Int)] = emailInputWords.groupMapReduce(identity)(_ => 1)(_ + _).toSeq.sortWith(_._2 > _._2)
    val illegalPhrasesUsed: Seq[(String, Int)] = wordOccurrences.filter(phrase => illegalPhrases.contains(phrase._1))
    val illegalPhraseCount: Int = illegalPhrasesUsed.map(_._2).sum

    new Report(emailInput, illegalPhrasesUsed, illegalPhraseCount, wordOccurrences, illegalPhraseCount >= minimumIllegalPhraseCount)
  }

}