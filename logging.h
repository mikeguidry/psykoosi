/*
 * logging.h
 *
 *  Created on: Jul 28, 2014
 *      Author: mike
 */

#ifndef LOGGING_H_
#define LOGGING_H_



namespace psykoosi {

  class Logging {
  	  public:
	  	  Logging();
	  	  ~Logging();
	  	  void LogMsg(char *, ...);

  	  private:
	  	  FILE *logging_fd;
	  	  char *filename;
  };
}


#endif /* LOGGING_H_ */
