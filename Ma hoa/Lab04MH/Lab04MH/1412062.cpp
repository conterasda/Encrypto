#include <iostream>
#include <time.h>
#include <conio.h>
#include "sha256.h"
using namespace std;

// Lớp chứa các phương thức phụ trợ
class Utility{
public:
static int SumMod(int a, int b, int n)
{
	while (a > n)
		a -= n;
	while (a < 0)
		a += n;
	while (b > n)
		b -= n;
	while (b < 0)
		b += n;
	int P = a + b;
	if (P > n) 
		return P-n;
	return P;
}

static int MulMod(int a, int b, int n)
{
	int S;
	if ((b & 1) == 0)
		S = 0;	
	else
		S = a;
	b = b >> 1;
	while (b>0)
	{
		a = SumMod(a, a, n);
		if ((b & 1) == 1)
			S = SumMod(S, a, n);
		b = b >> 1;
	}
	return S;
}

static int PowMod(int a, int b, int n)
{
	int y = 1;
	if (b == 0)
		return y;
	int A = a;
	if ((b & 1) == 1)
		y = a;
	b = b >> 1;
	while (b > 0)
	{
		A = MulMod(A, A, n);
		if ((b & 1) == 1)
			y = MulMod(A, y, n);
		b = b >> 1;
	}
	return y;
}
static int gcd(int a,int b)
{
	int g=0;
	while(((a&1)==0)&&((b&1)==0))
	{
		a = a >> 1;
		b = b >> 1;
		g++;
	}
	while (a>0)
	{
		while((a&1)==0)
			a=a>>1;
		while((b&1)==0)
			b=b>>1;
		if(a>=b)
		{
			a=(a-b)>>1;
		}
		else
			b=(b-a)>>1;
	}
	b=b<<g;
	return b;
}
static void Bezout(int a, int b, int &x, int &y)
{
	int u = a, v = b;
	int X = 1, Y = 0;
	x = 0;
	y = 1;
	while (u > 0)
	{
		while ((u & 1) == 0)
		{
			u = u >> 1;
			if (((X & 1) == 0) && ((Y & 1) == 0))
			{
				X = X >> 1;
				Y = Y >> 1;
			}
			else
			{
				X = (X + b) >> 1;
				Y = (Y - a) >> 1;
			}
		}
		while ((v & 1) == 0)
		{
			v = v >> 1;
			if (((x & 1) == 0) && ((y & 1) == 0))
			{
				x = x >> 1;
				y = y >> 1;
			}
			else
			{
				x = (x + b) >> 1;
				y = (y - a) >> 1;
			}
		}
		if (u >= v)
		{
			u -= v;
			X -= x;
			Y -= y;
		}
		else
		{
			v -= u;
			x -= X;
			y -= Y;
		}
	}
	while (x < 0)
		x += b;
}
static bool PrimeTest(int n)
{
	if (n < 2)
		return false;
	if ((n == 2) || (n == 3))
		return true;
	int m=n-1;
	int r=0;
	while ((m&1)==0)
	{
		r++;
		m=m>>1;
	}
	int t;
	int i = 1;
	do
	{
		t = PowMod(3, (1 << i)*m, n);
		if((t!=1)&&(t!=n-1))
			return false;		
		t = PowMod(2, (1 << i)*m, n);
		if ((t != 1) && (t != n - 1))
			return false;
		i++;
	}
	while (i <= r);
	
	return true;
}
static int prime_generator(int size)
{
	int t = (1 << (size - 1));
	srand(time(NULL));
	int i = t + 1 + rand()%t;
	if ((i & 1) == 0)
		i--;
	t = t << 1;
	while (i < t)
	{
		if (PrimeTest(i))
			return i;
		else
			i += 2;
	}
}
static int CRT(int size, int p[], int a[])
{
	int n = 1;
	for (int i = 0; i < size - 1; i++)
	{
		for (int j = i + 1; j < size; j++)
		{
			if (gcd(p[i], p[j]) != 1)
			{
				cout << "He khong phai la he dong du!";
				return -1;
			}
		}
		n *= p[i];
	}
	n *= p[size - 1];
	
	int m = 0;
	int *N = new int[size];
	int *M = new int[size];	
	for (int i = 0; i < size; i++)
	{
		N[i] = 1;
		for (int j = 0; j < size; j++)
		{
			if (i == j)
				continue;
			N[i] *= p[j];
		}
		int t;
		Bezout(N[i], p[i], M[i], t);
		M[i] = MulMod(M[i], a[i], n);
		t = MulMod(M[i], N[i], n);
		m = SumMod(m, t, n);		
	}	
	delete[] M;
	delete[] N;	
	return m;
}
};


class Crypto{
public:
	// Giải pháp RSA
	static void RSA_initialize(int size, int &d, int &e, int &p, int &q)//xuất thêm giá trị p và q để giải mã nhanh và công bố n
	{
		p = Utility::prime_generator(size);
		q = Utility::prime_generator(size + 1);
		srand(time(NULL));
		int k = rand() % (2 * size - 1) + 1;
		int phi = (p - 1)*(q - 1);
		int n = p*q;
		e = (1 << k) + 1;
		while (Utility::gcd(e, phi) != 1)//vì phi chẵn nên ta chỉ xét các giá trị e lẻ
		{
			e = e + 2;
		}
		int t;
		Utility::Bezout(e, phi, d, t);		
	}
	static int RSA_encrypt(int n, int e, int m)
	{
		return Utility::PowMod(m, e, n);
	}
	static int RSA_decrypt(int n, int d, int c)
	{
		return Utility::PowMod(c, d, n);
	}
	static int RSA_decryptCRT(int p, int q, int d, int c)
	{
		if ((d < p - 1) || (d < q - 1)) //nếu d<p-1 hay d<p-2 thì giải mã nhanh bằng CRT vô nghĩa
			return Utility::PowMod(c, d, p*q);
		int d1, d2;
		d1 = d % (p - 1);
		d2 = d % (q - 1);
		int P[2] = { p, q };
		int a[2] = { Utility::PowMod(c, d1, p), Utility::PowMod(c, d2, q) };
		return Utility::CRT(2, P, a);
	}

	//Chữ ký số bằng phương pháp RSA
	struct DigitalSignature {

		int m, s;

	};
	static int hash(int m)
	{
		char *a = (char*)&m;//chuyển các bit của thông điệp vào chuỗi a
		string in;
		for (int i = 0; i < 4; i++)
		{
			in += a[i];
		}
		string out = sha256(in); //sử dụng hàm băm SHA2-256bits		
		unsigned int* i = (unsigned int *)(out.c_str());
		return i[0] >> 5;//chỉ lấy 32-5=27 bits đầu của giá trị băm
	}
	static DigitalSignature* DigitalSignature_Sign(int d, int m, int n)
	{		
		DigitalSignature* DS = new DigitalSignature;
		DS->m = m;
		DS->s = Utility::PowMod(hash(m), d, n);
		return DS;
	}
	static bool DigitalSignature_Verify(DigitalSignature* x, int e, int n)
	{
		int signature = Utility::PowMod(x->s, e, n);
		return (hash(x->m) == signature);
	}
};

// Hàm main test chương trình
int main()
{
	int d, e, p, q;
	Crypto::RSA_initialize(14, d, e, p, q);
	int n = p*q;
	int m = 145;//thông điệp cần ký
	Crypto::DigitalSignature* S = Crypto::DigitalSignature_Sign(d, m, n);
	cout << "chu ky cho thong diep:" << S->s << endl;
	if (Crypto::DigitalSignature_Verify(S, e, n))
		cout << "Thong diep duoc xac thuc!" << endl;
	_getch();
	return 0;
}



