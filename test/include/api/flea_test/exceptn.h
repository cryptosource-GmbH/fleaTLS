/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_exceptn__H_
#define _flea_exceptn__H_

#include <exception>
#include <string>

class test_utils_exceptn_t : public std::exception
{
public:

  /**
   * Get the message of the exception.
   */
  const char* what() const throw() {return msg.c_str();}

  test_utils_exceptn_t(const std::string& m = "Unknown error"){set_msg(m);}

  virtual ~test_utils_exceptn_t() throw() { }

protected:
  void set_msg(const std::string& m){msg = "test_utils: " + m;}

private:
  std::string msg;
};


#endif /* h-guard */
