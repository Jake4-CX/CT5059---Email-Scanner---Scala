package lat.jack.emailscanner

import scala.collection.MapView

object Main extends App {

  private val illegalPhrases: List[String] = List("threat", "vulnerabilities", "attack", "loopholes", "whitelist", "blacklist", "hash", "encryption")
  private var emailInput: String = "You may seek him in the basement, you may look up in the air"
  emailInput = "I have installed a malware onto their system, it will encrypt all their files by using that vulnerability that you have found. The attack will start on friday which will exploit the loopholes in their system. It will also wipe the whitelist and blacklist and their system will collapse."

  emailInput = emailInput.toLowerCase() // Normalize the string - to lowercase

  private val emailInputWords: Array[String] = emailInput.split(" ")

  private val wordOccurrences: Seq[(String, Int)] = emailInputWords.groupMapReduce(identity)(_ => 1)(_ + _).toSeq.sortWith(_._2 > _._2)
  // println(wordOccurrences)

  private var illegalPhrasesUsed: Seq[(String, Int)] = Seq()
  private var illegalPhraseCount: Int = 0

  wordOccurrences.foreach((word, occurrence) => {
    if (illegalPhrases.contains(word) && occurrence > 2) {
      illegalPhrasesUsed :+ (word, occurrence)
      illegalPhraseCount += occurrence
    }
  })


  println(s"Email: ${emailInput}")
  // Print the list of illegal phrases used (key) from illegalPhrasesUsed
  println("Phrases used: ")
  illegalPhrasesUsed.foreach((word, occurrence) => {
    println(word)
  })


  if (wordOccurrences.length > 5 && illegalPhraseCount > 5) {
    println("This is a Suspicious File")
  } else {
    println("This file is Benign")
  }

}