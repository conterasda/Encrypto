#include <iostream>
#include <string>
#include <string.h>
#include <fstream>
#include <time.h>
#include "ZUC.h"
#include "aes.h"

using namespace std;

class AES_Mode{
public:
	static string init(ifstream& is)
	{
		string data;
		string t;
		getline(is, t);
		data += t;
		while (!is.eof())
		{
			getline(is, t);
			data += '\n';
			data += t;
		}
		return data;
	}
	//Phương thức thêm padding
	static void Padding(string& data)
	{ 
		char padding_size = (char)(16 - (data.size() + 1) % 16);
		for (int i = 0; i < padding_size; i++)
		{
			srand(time(NULL));
			data += rand();
		}
		data = padding_size + data;			
	}
	//Phương thức xóa padding
	static void DePadding(string& data)
	{ 
		char padding_size = data[0];
		int size = data.size() - padding_size - 1;
		data = data.substr(1, size);
	}
	//Electronic Codebook(ECB)
	static string ECB_Encrypt(string data, uint8* key, int nbits)
	{
		aes_context* ctx = new aes_context;
		aes_set_key(ctx, key, nbits);
		uint8 t1[16];
		uint8 t2[16];
		string out;
		int i = 0;
		while (i < data.size() / 16)
		{			
			for (int j = 0; j < 16; j++)
			{
				t1[j] = data[i * 16 + j];
			}
			aes_encrypt(ctx, t1, t2);
			for (int j = 0; j < 16; j++)
			{
				out += t2[j];
			}
			i++;
		}
		delete ctx;
		return out;
	}
	static string ECB_Decrypt(string data, uint8* key, int nbits)
	{
		aes_context* ctx = new aes_context;
		aes_set_key(ctx, key, nbits);
		uint8 t1[16];
		uint8 t2[16];
		string out;
		int i = 0;
		while (i < data.size() / 16)
		{			
			for (int j = 0; j < 16; j++)
			{
				t1[j] = data[i * 16 + j];
			}
			aes_decrypt(ctx, t1, t2);
			for (int j = 0; j < 16; j++)
			{
				out += t2[j];
			}
			i++;
		}
		delete ctx;
		return out;
	}
	//Cipher Block Chaining (CBC)
	static string CBC_Encrypt(string data, uint8* key, int nbits, uint8 IV[16])
	{
		aes_context* ctx = new aes_context;
		aes_set_key(ctx, key, nbits);
		uint8 t1[16];
		uint8 t2[16];
		for (int j = 0; j < 16; j++)
		{
			t2[j] = IV[j];
		}
		string out;
		int i = 0;
		while (i < data.size() / 16)
		{
			for (int j = 0; j < 16; j++)
			{
				t1[j] = data[i * 16 + j];
				t1[j] = t1[j] ^ t2[j];
			}
			aes_encrypt(ctx, t1, t2);
			for (int j = 0; j < 16; j++)
			{
				out += t2[j];
			}
			i++;
		}
		delete ctx;
		return out;
	}
	static string CBC_Decrypt(string data, uint8* key, int nbits, uint8 IV[16])
	{
		aes_context* ctx = new aes_context;
		aes_set_key(ctx, key, nbits);
		uint8 t1[16];
		uint8 t2[16];
		uint8 t3[16];
		for (int j = 0; j < 16; j++)
		{
			t3[j] = IV[j];
		}
		string out;
		int i = 0;
		while (i < data.size() / 16)
		{
			for (int j = 0; j < 16; j++)
			{
				t1[j] = data[i * 16 + j];
			}
			aes_decrypt(ctx, t1, t2);
			for (int j = 0; j < 16; j++)
			{
				t2[j] = t2[j] ^ t3[j];
				out += t2[j];
				t3[j] = t1[j];
			}
			i++;
		}
		delete ctx;
		return out;
	}
	//Output feed back (OFB)
	static string OFB_Encrypt(string data, uint8* key, int nbits, uint8 IV[16])
	{
		aes_context* ctx = new aes_context;
		aes_set_key(ctx, key, nbits);
		uint8 t1[16];
		uint8 t2[16];
		uint8 t3[16];
		for (int j = 0; j < 16; j++)
		{
			t3[j] = IV[j];
		}
		string out;
		int i = 0;
		while (i < data.size() / 16)
		{
			aes_encrypt(ctx, t3, t2);
			for (int j = 0; j < 16; j++)
			{
				t1[j] = data[i * 16 + j];
				t3[j] = t2[j];
				t2[j] = t1[j] ^ t2[j];
				out += t2[j];
			}
			i++;
		}
		delete ctx;
		return out;
	}
			//OFB_Decrypt có cấu trúc hoàn toàn giống OFB_Encrypt, thay tham số đầu vào là bản mã thay cho bản rõ
	static string OFB_Decrypt(string data, uint8* key, int nbits, uint8 IV[16])
	{
		aes_context* ctx = new aes_context;
		aes_set_key(ctx, key, nbits);
		uint8 t1[16];
		uint8 t2[16];
		uint8 t3[16];
		for (int j = 0; j < 16; j++)
		{
			t3[j] = IV[j];
		}
		string out;
		int i = 0;
		while (i < data.size() / 16)
		{
			aes_encrypt(ctx, t3, t2);
			for (int j = 0; j < 16; j++)
			{
				t1[j] = data[i * 16 + j];
				t3[j] = t2[j];
				t2[j] = t1[j] ^ t2[j];
				out += t2[j];
			}
			i++;
		}
		delete ctx;
		return out;
	}
	//Cipher feed back (CFB)
	static string CFB_Encrypt(string data, uint8* key, int nbits, uint8 IV[16])
	{
		aes_context* ctx = new aes_context;
		aes_set_key(ctx, key, nbits);
		uint8 t1[16];
		uint8 t2[16];
		uint8 t3[16];
		for (int j = 0; j < 16; j++)
		{
			t3[j] = IV[j];
		}
		string out;
		int i = 0;
		while (i < data.size() / 16)
		{
			aes_encrypt(ctx, t3, t2);
			for (int j = 0; j < 16; j++)
			{
				t1[j] = data[i * 16 + j];
				t2[j] = t1[j] ^ t2[j];
				t3[j] = t2[j];
				out += t2[j];
			}
			i++;
		}
		delete ctx;
		return out;
	}
	static string CFB_Decrypt(string data, uint8* key, int nbits, uint8 IV[16])
	{
		aes_context* ctx = new aes_context;		
		aes_set_key(ctx, key, nbits);
		uint8 t1[16];
		uint8 t2[16];
		uint8 t3[16];
		for (int j = 0; j < 16; j++)
		{
			t3[j] = IV[j];
		}
		string out;
		int i = 0;
		while (i < data.size() / 16)
		{
			aes_encrypt(ctx, t3, t2);
			for (int j = 0; j < 16; j++)
			{
				t1[j] = data[i * 16 + j];
				t3[j] = t1[j];
				t2[j] = t1[j] ^ t2[j];
				out += t2[j];
			}
			i++;
		}
		delete ctx;
		return out;
	}
};
int main()
{
	cout << "Nhap yeu cau:\n1.Test cac mode thuat toan AES\n2.Test thuat toan ZUC" << endl;
	int yc;
	cin >> yc;
	if (yc == 1)
	{
		//IV mặc định
		uint8 IV[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
		//Đọc dữ liệu cần mã hóa từ file in.txt
		ifstream f("in.txt");
		string in = AES_Mode::init(f);
		cout << "Du lieu dau vao:" << endl << in << endl;
		//padding cho dữ liệu đầu vào
		AES_Mode::Padding(in);
		//Phát sinh khoá độ dài<256
		srand(time(NULL));
		int size = rand() % 256;
		uint8 *key = new uint8[size];
		for (int i = 0; i < size; i++)
		{
			srand(time(NULL) + i);
			key[i] = rand() % 256;
		}
		cout << "Khoa duoc phat sinh ngau nhien:" << key << endl;
		//Lựa chọn mode
		cout << "Chon Mode:\n\t1.ECB\n\t2.CBC\n\t3.OFB\n\t4.CFB" << endl;
		cin >> yc;
		string e, d;

		switch (yc)
		{
		case 1:
		{
				  e = AES_Mode::ECB_Encrypt(in, key, 256);
				  cout << "Du lieu da ma hoa bang ECB:" << endl << e << endl;
				  d = AES_Mode::ECB_Decrypt(e, key, 256);
		}
			break;
		case 2:
		{
				  //phát sinh IV ngẫu nhiên
				  for (int i = 0; i < 16; i++)
				  {
					  srand(time(NULL));
					  IV[i] = rand() % 256;
				  }
				  e = AES_Mode::CBC_Encrypt(in, key, 256, IV);
				  cout << "Du lieu da ma hoa bang CBC:" << endl << e << endl;
				  d = AES_Mode::CBC_Decrypt(e, key, 256, IV);
		}
			break;
		case 3:
		{
				  e = AES_Mode::OFB_Encrypt(in, key, 256, IV);
				  cout << "Du lieu da ma hoa bang OFB:" << endl << e << endl;
				  d = AES_Mode::OFB_Decrypt(e, key, 256, IV);
		}
			break;
		default:
		{
				   e = AES_Mode::CFB_Encrypt(in, key, 256, IV);
				   cout << "Du lieu da ma hoa bang CFB:" << endl << e << endl;
				   d = AES_Mode::CFB_Decrypt(e, key, 256, IV);
		}
		}
		AES_Mode::DePadding(d);
		cout << endl<<"Giai ma du lieu:" << endl << d << endl;
		delete key;
		return 0;
	}
	else
	{
		u8 key[16] = { 0x17, 0x3d,0x14, 0xba, 0x50, 0x03, 0x73, 0x1d, 0x7a, 0x60, 0x04, 0x94, 0x70, 0xf0, 0x0a, 0x29 };
		u32 count = 0x66035492;
		u32 m[7] = { 0x6cf65340, 0x735552ab, 0x0c9752fa, 0x6f9025fe, 0x0bd675d9,0x005875b2, 0x00000000 };
		u32 c[7],t[7];
		//Test thuat toan 128-EEA3
		EEA3(key, count, 15, 0, 193, m, c);
		cout << "Ma hoa doan du lieu bang EEA3:"<<endl<<"6cf65340, 735552ab, 0c9752fa, 6f9025fe, 0bd675d9, 005875b2, 00000000 ";
		cout << endl << "Du lieu duoc ma hoa: " << endl;
		for (int i = 0; i < 7; i++)
		{
			cout << c[i]<<" ";
		}
		cout << endl;
		EEA3(key, count, 15, 0, 193, c, t);
		cout << "Giai ma du lieu: ";
		for (int i = 0; i < 7; i++)
		{
			cout <<hex<< t[i] << " ";
		}
		cout << endl;	
		//Test thuat toan 128-EIA3
		u8 key1[16] = { 0x47, 0x05, 0x41, 0x25, 0x56, 0x1e, 0xb2, 0xdd, 0xa9, 0x40, 0x59, 0xda, 0x05, 0x09, 0x78, 0x50 };
		u32 m1[3] = { 0, 0, 0 };
		u32 MAC[3];
		EIA3(key, 0x561eb2dd, 14, 96, 193, m1, MAC);
		cout << endl << "Tao ma nhan dang tin nhan MAC bang EIA3 cho mau tin:" << endl << "0, 0, 0 ";
		cout << endl << "MAC cua tin nhan nay: " << endl;
		for (int i = 0; i < 3; i++)
		{
			cout << MAC[i] << " ";
		}
		cout << endl;
		return 0;
	}
}