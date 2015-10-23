	// cdb hashing.. for other unrelated project.. but useful if you need some kinda hashing here..
unsigned int cdb_hashadd(unsigned int h,unsigned char c) {
    h += (h << 5);
    return h ^ c;
}

unsigned int cdb_hash(const char *buf,unsigned int len) {
    unsigned int h;

    h = 5381;
    while (len) {
        h = cdb_hashadd(h,*buf++);
        --len;
    }
    return h;
}
// end cdb
