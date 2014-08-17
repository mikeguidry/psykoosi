/* File : psy.i */
 
%module psy
 
%{
#include "../psykoosi_lib/psykoosi.h"
using namespace psykoosi;
%}
 
/* Let's just grab the entire header files here */
%include "../psykoosi_lib/psykoosi.h"
