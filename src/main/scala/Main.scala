package lat.jack.emailscanner

import java.io.File
import scala.collection.MapView
import scala.collection.immutable.HashMap
import scala.io.Source

object Main {
  private val illegalPhrases: List[String] = List("threat", "vulnerabilities", "attack", "loopholes", "whitelist", "blacklist", "hash", "encryption")
  private val minimumIllegalPhraseCount: Int = 5
  private case class Email(email: String, illegalPhrases: List[String], illegalPhraseCount: Int, suspicious: Boolean)
  private val emails: HashMap[String, Email] = HashMap[String, Email]()

  // Create a

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
    if (args.length == 0) {
      println("No parameters have been passed in. Please pass in either -F or -D")
      println("For more information, please run the program with the -H parameter")
    } else if (args.length == 1) {
      if (args(0) == "-H") {
        println("This program will scan an email for suspicious phrases")
        println("To run the program, please pass in either -F or -D")
        println("-F will scan a single file")
        println("-D will scan all the files in a directory")
      } else {
        println("Please pass in either -F or -D")
        println("For more information, please run the program with the -H parameter")
      }
    } else if (args.length == 2) {
      if (args(0) == "-F") {
        val fileContents = readFile(args(1))
        scanEmail(fileContents)
        // Main.main(Array())
      } else if (args(0) == "-D") {
        val files = readDirectory(args(1))
        for (file <- files) {
          val fileContents = readFile(args(1) + "/" + file)
          scanEmail(fileContents)
          // Main.main(Array())
        }
      } else {
        println("Please pass in either -F or -D")
        println("For more information, please run the program with the -H parameter")
      }
    } else {
      println("Please pass in either -F or -D")
      println("For more information, please run the program with the -H parameter")
    }
  }

  private def scanEmail(emailInput: String) = {
    var email: String = emailInput

    email = email.toLowerCase() // Normalize the string - to lowercase

    email = email // Replace all characters that have accents with their non-accented equivalent
      .replaceAll("[áàâãåä]", "a")
      .replaceAll("[éèêë]", "e")
      .replaceAll("[íìîï]", "i")
      .replaceAll("[óòôõö]", "o")
      .replaceAll("[úùûü]", "u")
      .replaceAll("ç", "c")

    val emailInputWords: Array[String] = email.split(" ")

    val wordOccurrences: Seq[(String, Int)] = emailInputWords.groupMapReduce(identity)(_ => 1)(_ + _).toSeq.sortWith(_._2 > _._2)

    val illegalPhrasesUsed: Seq[(String, Int)] = wordOccurrences.filter(phrase => illegalPhrases.contains(phrase._1)) // min requirement = (phrase._2 >= 2)
    val illegalPhraseCount: Int = illegalPhrasesUsed.map(_._2).sum

    var build = ""
    var i = 0

    for (illegalPhrase <- illegalPhrasesUsed) {
      build += illegalPhrase._1 + s" (${illegalPhrase._2})"

      if (i < illegalPhrasesUsed.length - 1) {
        build += ", "
      } else build += "."

      i += 1
    }

    println(s"Email: ${emailInput}")
    println("")
    println(s"Total Illegal Phrases Used: $illegalPhraseCount")
    println(s"Illegal Phrases used $build")
    println("")

    if (wordOccurrences.length > 5 && illegalPhraseCount >= minimumIllegalPhraseCount) {
      println("This is a Suspicious File")
    } else {
      println("This file is Benign")
    }
  }

}