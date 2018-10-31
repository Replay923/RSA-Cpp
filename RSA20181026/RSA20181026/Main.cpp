#include "RSADecryptDemo.h"
#include "RSAEncryptDemo.h"

int main()
{
	cout << "+++++++++++++++++++++++++++++加密示例+++++++++++++++++++++++++++++" << endl;
	//启动加密示例
	RSAEncryptDemo::StartUp();
	cout << "+++++++++++++++++++++++++++++解密示例+++++++++++++++++++++++++++++" << endl;
	//启动解密示例
	RSADecryptDemo::StartUp();

	int i;
	cin >> i;
	return 0;
}