#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <C:/Users/administered/Desktop/idash2022/src/matrix.h>
using namespace std;

void read_data_faster(matrix<int64_t>& Ma, string& filename, int64_t rows, int64_t cols)
{
    fstream in(filename);
    if (!in.is_open())
    {
        cout << "open .txt fail!" << endl;
        return;
    }

    string line;
    Ma.resize(rows, cols); // ע����Ҫresize����txt�ļ��о����ά�ȶ�Ӧ
    for (int i = 0; i < rows; i++)
    {
        //cout << "Reading " << i+1 << "th line." << endl;
        getline(in, line);
        int nSPos = 0, nEPos = 0;
        nSPos = line.find('\t', nSPos); // ��1��tab��
        nSPos++;
        nSPos = line.find('\t', nSPos); // ��2��tab��
        nSPos++;
        nSPos = line.find('\t', nSPos); // ��3��tab��
        nSPos++;
        nSPos = line.find('\t', nSPos); // ��4��tab��
        // nSPos++;//�������ʼ��λ��
        nSPos++;
        for (int j = 0; j < cols; j++)
        {

            Ma(i, j) = line[nSPos + j * 2] - '0';

        }
    }
}
