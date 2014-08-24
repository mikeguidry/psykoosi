/* File : psykoosi.i */
 
%module psykoosi

%{
#include "../psykoosi_lib/psykoosi.h"
using namespace psykoosi;
%}
 
/* Let's just grab the entire header files here */
%include <std_string.i>
%include "../psykoosi_lib/psykoosi.h"
