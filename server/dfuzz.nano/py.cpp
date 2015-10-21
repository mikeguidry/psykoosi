#include <Python.h>




// base64 stuff.. i thikn nginx has it built in but i didnt feel like going through the API/documention/source
static const unsigned char pr2six[256] =
{
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63, 52, 53, 54,
    55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64, 64, 0, 1, 2, 3,
    4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
    22, 23, 24, 25, 64, 64, 64, 64, 64, 64, 26, 27, 28, 29, 30, 31, 32,
    33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    50, 51, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

char *
base64_decode(char *bufcoded, int* len)
{
    int nbytesdecoded;
    register const unsigned char *bufin;
    register char *bufplain;
    register unsigned char *bufout;
    register int nprbytes;
    
    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);
    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;
    bufplain = (char *)malloc(nbytesdecoded + 1);
    bufout = (unsigned char *) bufplain;
    bufin = (const unsigned char *) bufcoded;
    
    while (nprbytes > 0) {
        *(bufout++) = (unsigned char) (pr2six[bufin[0]] << 2 | pr2six[bufin[1]] >> 4);
        if (nprbytes == 2) break;
        *(bufout++) = (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
        if (nprbytes == 3) break;
        *(bufout++) = (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
        bufin += 4;
        nprbytes -= 4;
    }
    *bufout = 0;
    *len=((unsigned char *)bufout -  (unsigned char *)bufplain);
    return bufplain;
}

static const char basis_64[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *base64_encode(unsigned char *s, int len) {
    register int i;
    register char *p, *e;
    
    p = e = (char *) malloc((((len + 2) / 3 * 4)) + 1);
    
    for (i = 0; i < len; i += 3) {
        *p++ = basis_64[s[i] >> 2];
        if (i == len) break;
        if ((i + 1) == len) {
            *p++ = basis_64[((s[i] & 0x03) << 4)];
            break;
        } else {
            *p++ = basis_64[((s[i] & 0x03) << 4) | ((int) (s[i+1] & 0xF0) >> 4)];
        }
        if ((i + 2) == len) {
            *p++ = basis_64[((s[i+1] & 0x0F) << 2)];
            break;
        } else {
            *p++ = basis_64[((s[i+1] & 0x0F) << 2) | ((int) (s[i+2] & 0xC0) >> 6)];
        }
        *p++ = basis_64[  s[i+2] & 0x3F];
    }
    *p = '\0';
    return e;
} 
// end base64



char *GenPDF(int a, int *_len) {
    PyObject *pName=NULL, *pModule=NULL, *pFunc=NULL;
    PyObject *pArgs=NULL, *pValue=NULL;
    PyObject *pArray=NULL;
    int size = 0;
    char *data = NULL;
    
    pName = PyString_FromString("generate");
    pModule = PyImport_Import(pName);
    Py_DECREF(pName);

    if (pModule == NULL) goto end;
	pFunc = PyObject_GetAttrString(pModule, "generate");
    if (!(pFunc && PyCallable_Check(pFunc))) goto end;

	// setup and convert arguments for python script
	pArgs = PyTuple_New(1);
	pValue = PyInt_FromLong(a);
    if (!pValue) goto end;
	PyTuple_SetItem(pArgs, 0, pValue);
    
	// call python function
	pValue = PyObject_CallObject(pFunc, pArgs);
	Py_XDECREF(pArgs);
    
	// if return value.. then we wanna convert and print
	if (pValue != NULL && !PyErr_Occurred()) {
	    pArray = PyByteArray_FromObject(pValue);
        if (pArray == NULL) goto end;
	    size = PyByteArray_Size(pArray);
	    if ((data = (char *)malloc(size+1)) == NULL) goto end;
	    //if (data == NULL) return NULL;
	    memcpy(data, PyByteArray_AsString(pArray), size);
	    *_len = size;
	} else {
	    PyErr_Print();
    }

    
end:;
    Py_XDECREF(pFunc);
    Py_XDECREF(pArray);
    Py_XDECREF(pValue);
    Py_XDECREF(pFunc);
    Py_XDECREF(pModule);
    Py_XDECREF(pArgs);


    
    
    return data;
    /*if (data != NULL) {
	ret = base64_decode(data, &size);
	*_len = size;
	free(data);
	return ret;
    }*/
}



int main(int argc, char *argv[]) {
    int pdfsize = 0;
    FILE *fd;
    char *pdfdata = NULL;
    
    Py_Initialize();
    PySys_SetArgv(argc, argv);  
        
    pdfdata = GenPDF(1, &pdfsize);
    printf("ret %p pdfsize %d\n", pdfdata, pdfsize);
    if (pdfdata != NULL) {
	printf("writing to blah.pdf\n");
	
        fd = fopen("blah.pdf","wb");
	if (fd) {
        	int wrote = fwrite(pdfdata, 1, pdfsize, fd);
		printf("size: %d wrote: %d\n", pdfsize, wrote);
		fclose(fd);    
	}
    }
    
    
    Py_Finalize();
}