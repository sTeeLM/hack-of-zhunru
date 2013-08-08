#include "packet.h"
#include <string.h>
#include <strings.h>

#define BNAC_MAX_OPTIONS 256

packet_t::packet_t()
{

}

packet_t::~packet_t()
{

}

#ifdef WIN32
static char *index(const char *s, int c)
{
    char * p = (char *)s;
    if(NULL == s) return NULL;
    for(int i = 0 ; i < c ; i++) {
        if(*p == c) {
            return p;
        }
        p++;
    }

    return NULL;
}
#endif

const std::string & packet_t::get_header() const
{
    return m_header;
}

const std::string & packet_t::set_header(const std::string & header)
{
    m_header = header;
    return m_header;
}

const std::string & packet_t::get_option(const std::string & key)
{
    return m_options[key];
}

const std::string & packet_t::set_option(const std::string & key, const std::string & val)
{
    m_options[key] = val;
    return m_options[key];
}

void packet_t::clear()
{
    m_header = "";
    m_options.clear();
}

bool packet_t::option_exist(const std::string & key) const
{
    return m_options.find(key) != m_options.end();
}

// 尼玛，md5你们不转玛，我就不得不写这个特殊的赋值函数
void packet_t::append_str(std::string & str, void * buffer, size_t len)
{
    size_t i;
    char * c_buffer = (char *) buffer;
    for(i = 0 ; i < len; i ++) {
        str.push_back(c_buffer[i]);
    }
}

bool packet_t::from_buffer(void * buffer, size_t len)
{

    char * c_buffer = (char * ) buffer;
    char * options[BNAC_MAX_OPTIONS] = {0};
    int length[BNAC_MAX_OPTIONS] = {0};
    char *p1, *p2, *p3;
    int i, j;
    if(buffer == NULL || len < 4)
        return false;

    if(c_buffer[len - 4] != '\r' || c_buffer[len - 3] != '\n'
    ||c_buffer[len - 2] != '\r' || c_buffer[len - 1] != '\n') {
        return false;
    }

    clear();

    // round 1 set \r\n to 0
    p3 = c_buffer;
    j = 0;
    for(i = 0 ; i < len - 1 && j < BNAC_MAX_OPTIONS; i ++) {
        p1 = c_buffer + i;
        p2 = p1 + 1;
        if(*p1 == '\r' && *p2 == '\n') {
            *p1 = 0;
            *p2 = 0;
            length[j] = p1 - p3;
            if(length[j] <= 0) break;
            options[j] = p3;
            p3 = c_buffer + i + 2;
            j++;
        }
    }

    if(j == 0) {
        return false;
    }

    append_str(m_header, options[0], length[0]);
    // get options
    for(i = 1; i < j ; i++) {
        std::string key, val;
        int key_len, val_len;

        p1 = options[i];
        p2 = index(p1, ':');
        if(p2 == NULL)
            return false;
        *p2 = 0;
        key_len = p2 - p1;
        p2 ++;
        if(*p2 == 0)
            return false;

        val_len = length[i] - key_len - 1;

        append_str(key, p1, key_len);
        append_str(val, p2, val_len);

        m_options[key] = val;
    }
    return true;
}

size_t packet_t::to_buffer(void * buffer, size_t len) const
{
    size_t ret = 0;
    std::map<std::string,std::string>::const_iterator iter = m_options.begin();
    size_t size = get_size();
    char * c_buffer = (char *)buffer;

    if(size > len || NULL == buffer)
        return 0;
    
    memcpy(c_buffer + ret, m_header.data(), m_header.size());
    ret += m_header.size();
    c_buffer[ret] = '\r';
    c_buffer[ret + 1] = '\n';
    ret += 2;
    for(iter = m_options.begin() ; iter != m_options.end() ; iter ++) {
        memcpy(c_buffer + ret, iter->first.data(), iter->first.size());
        ret += iter->first.size();
        c_buffer[ret] = ':';
        ret ++;
        memcpy(c_buffer + ret, iter->second.data(), iter->second.size());
        ret += iter->second.size();
        c_buffer[ret] = '\r';
        c_buffer[ret + 1] = '\n';
        ret += 2;
    }
    c_buffer[ret] = '\r';
    c_buffer[ret + 1] = '\n';
    ret += 2;

    return ret;
}

size_t packet_t::get_size() const
{
    size_t ret = 0;
    
    std::map<std::string,std::string>::const_iterator iter = m_options.begin();

    if(m_header.size() != 0) {
        ret = m_header.size() + 2;
        for(iter = m_options.begin() ; iter != m_options.end() ; iter ++) {
            ret += iter->first.size() + 1;
            ret += iter->second.size();
            ret += 2;
        }
        ret += 2;
    }
    return ret;
}  

