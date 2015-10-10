/*
 * polymorph.h
 *
 * Declaration for polymorph class.. see polymorph.cpp for more details relating to the process.
 *      Author: mike
 */

#ifndef POLYMORPH_H_
#define POLYMORPH_H_

namespace psykoosi {

  class Polymorph {
  	  public:
	  Polymorph();
	  ~Polymorph();

	  DisassembleTask::InstructionInformation *InstructionReplace(DisassembleTask::InstructionInformation *Original);

  	  private:
  };

}


#endif /* POLYMORPH_H_ */
