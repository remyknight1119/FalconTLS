


int
tls_do_write(TLS *s, int type)
{
    size_t  written = 0;
    int     ret = 0;

    ret = tls_write_bytes(s, type, &s->init_buf->data[s->init_off],
            s->init_num, &written);

    s->init_off += written;
    s->init_num -= written;
    return 0;
}
