#ifndef OUTERROR_H
#define OUTERROR_H

typedef enum ErrorInfo {
	Successful = 0,// 成功

	// build
	ReadConfigFile = 1,// 读取配置文件失败
	ChangeDir,// 无法切换目录
	CreateCpkgDir,// 没找到.cpkg文件夹
	CreateConfigJsonFile,// 无法创建配置文件的json内容
	CreateLibsDir,// 没找到libs文件夹
	LibNotExist,// 库文件不存在
	CreateIncludeDir,//没找到include文件夹
	IncludeNotExist,// 头文件不存在
	GzipConfigFile,// 无法压缩配置文件
	GzipPocketFile,// 无法压缩libs和include文件夹
	ParseConfigFormat,// 无法解析配置文件格式
	CreateEndFile, // 无法创建最终文件

	// install
	CreateConfigFile,
}ErrorInfo;

void ErrorArg(int errorCode);
#endif // OutError.h
