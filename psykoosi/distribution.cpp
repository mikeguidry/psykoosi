/* distribution of fuzzing tasks

   the fuzzer is going to use nanomsg to communicate to the 'server' to specify
   it found a location for fuzzing (IO, Net, etc), or to ask for fuzzing instructions
   
   the client should first specify it's old identifiers for virtual memory that
   has already been downloaded to this side.. so it will fuzz faster without having
   to redownload that code... it should do an 80%/20% rule for this so it also
   works on other projects... server side should distribute accordingly to its 
   operations..
   
   this also allows logemu.dll injected into machines on adware, or intentionally
   to upload their areas for fuzzing


   this needs to allow direct access to all classes to insert the
   necessary memory, code, etc and then it needs to be wiped after the tasks
   are completed...
   
   so brute force, bit flip, etc can all be distributed in ranges, and
   it could be mixed with a variety of software so no single process fuzzes
   the same software consistently.. this allows it to work against
   as many programs as the injectable DLL creates information regarding
   or allows an adware network to upload multiple versions of all apps
   to fuzz everything users generally users
   
   create a server side statistics engine to keep track of all software
   on each desktop machine and focus on the ones with higher counts
   focus and emulate the top versions  (highest count) of each
   application being fuzzed
    

*/