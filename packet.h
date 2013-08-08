#ifndef __BNAC_PACKET_H__
#define __BNAC_PACKET_H__

#include <stdint.h>
#include <string>
#include <map>

class packet_t
{
public:
	packet_t();
	virtual ~packet_t();
public:
	const std::string & get_header() const;
	const std::string & set_header(const std::string & header);
	const std::string & get_option(const std::string & key);
	const std::string & set_option(const std::string & key, const std::string & val);
	bool option_exist(const std::string & key) const;
	void clear();
	size_t to_buffer(void * buffer, size_t len) const;
	bool from_buffer(void * buffer, size_t len);
	static void append_str(std::string & str, void * buffer, size_t len);
private:
	size_t get_size() const;
public:
	std::string m_header;
	std::map<std::string, std::string> m_options;

};

#endif
