/* fleaTLS cryptographic library
Copyright (C) 2015-2019 cryptosource GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

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
