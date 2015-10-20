-- MySQL dump 10.13  Distrib 5.5.31, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: dfuzz
-- ------------------------------------------------------
-- Server version	5.5.31-0ubuntu0.12.04.2

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `complete`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `complete` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `application` varchar(25) NOT NULL,
  `version` varchar(25) NOT NULL,
  `ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `sample_id` int(25) NOT NULL,
  `byte` int(25) NOT NULL,
  `mode` int(25) NOT NULL,
  `count` int(25) NOT NULL,
  `hash` varchar(64) NOT NULL,
  `exceptions` int(25) NOT NULL,
  `time` int(25) NOT NULL,
  PRIMARY KEY (`id`,`application`,`version`,`sample_id`,`byte`,`mode`,`hash`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `complete`
--

LOCK TABLES `complete` WRITE;
/*!40000 ALTER TABLE `complete` DISABLE KEYS */;
/*!40000 ALTER TABLE `complete` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `exceptions`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `exceptions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `operation_id` int(25) NOT NULL DEFAULT '1',
  `application` varchar(25) NOT NULL,
  `version` varchar(25) NOT NULL,
  `exception_address` varchar(25) NOT NULL,
  `exception_code` varchar(25) NOT NULL,
  `sample_id` int(25) NOT NULL,
  `byte` int(25) NOT NULL,
  `newbyte` varchar(25) NOT NULL,
  `ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `mode` int(11) NOT NULL DEFAULT '1',
  `hash` varchar(64) NOT NULL,
  `ip` varchar(16) NOT NULL,
  `extra` mediumblob,
  `checked` int(25) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`,`operation_id`,`application`,`sample_id`,`version`,`hash`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `exceptions`
--

LOCK TABLES `exceptions` WRITE;
/*!40000 ALTER TABLE `exceptions` DISABLE KEYS */;
/*!40000 ALTER TABLE `exceptions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `operations`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `operations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `application` varchar(25) NOT NULL,
  `version` varchar(25) NOT NULL,
  `sample` varchar(25) NOT NULL,
  `thinapp` int(25) NOT NULL,
  `max_clients` int(25) NOT NULL DEFAULT '500',
  `queue_timeout` int(11) DEFAULT NULL,
  `memory_only` int(25) NOT NULL DEFAULT '0',
  `trace_mode` int(25) NOT NULL DEFAULT '0',
  `created` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `enabled` int(25) NOT NULL DEFAULT '1',
  `operating_system` int(25) NOT NULL DEFAULT '1',
  `ipc_file` varchar(25) NOT NULL DEFAULT '/tmp/dfuzz.ipc',
  `inject_dll` int(25) NOT NULL DEFAULT '0',
  `dll` varchar(25) NOT NULL DEFAULT '/tmp/dll/inject.dll',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `operations`
--

LOCK TABLES `operations` WRITE;
/*!40000 ALTER TABLE `operations` DISABLE KEYS */;
/*!40000 ALTER TABLE `operations` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `queue`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `queue` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `application` varchar(25) NOT NULL,
  `version` varchar(25) NOT NULL DEFAULT '1',
  `ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `ip` varchar(16) NOT NULL DEFAULT '0.0.0.0',
  `hash` varchar(64) NOT NULL,
  `sample_id` int(11) NOT NULL DEFAULT '1',
  `byte` int(11) NOT NULL DEFAULT '0',
  `mode` int(11) NOT NULL DEFAULT '1',
  `count` int(11) NOT NULL DEFAULT '16',
  PRIMARY KEY (`id`,`application`,`version`,`hash`,`sample_id`,`byte`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `queue`
--

LOCK TABLES `queue` WRITE;
/*!40000 ALTER TABLE `queue` DISABLE KEYS */;
/*!40000 ALTER TABLE `queue` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `samples`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `samples` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `application` varchar(25) NOT NULL,
  `version` varchar(25) NOT NULL,
  `generator` varchar(25) NOT NULL,
  `ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `bytes` int(25) NOT NULL,
  `data` mediumblob,
  `exhausted` int(11) NOT NULL DEFAULT '0',
  `initial_file` mediumblob,
  PRIMARY KEY (`id`,`application`,`version`,`generator`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `samples`
--

LOCK TABLES `samples` WRITE;
/*!40000 ALTER TABLE `samples` DISABLE KEYS */;
/*!40000 ALTER TABLE `samples` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2013-07-02 20:40:59
