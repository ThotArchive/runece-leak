#include "console.h"; 

void Success(std::string str) {
	std::cout << "[ " << termcolor::green << " + " << termcolor::reset << " ] - " << str << std::endl;
}

void Error(std::string str) {
	std::cout << "[ " << termcolor::red << " ! " << termcolor::reset << " ] - " << str << std::endl;
}


void BygayBanner() {
	

	std::cout << termcolor::yellow << termcolor::bold << R"(
	


		___  _   _ ____ ____ _   _ 
		|__]  \_/  | __ |__|  \_/  
		|__]   |   |__] |  |   |   
                           
	                  V1.8*
		    Level 2 Executor
	)" << termcolor::reset << std::endl;

}