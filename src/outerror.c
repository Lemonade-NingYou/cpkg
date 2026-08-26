/*
 * outerror.c
 * 错误信息输出模块
 * 根据传入的错误码，向标准错误流输出对应的错误描述
 */

#include "../include/outerror.h"
#include <stdio.h>
#include <stdlib.h>

/**
 * ErrorArg - 根据错误码打印对应的错误信息
 * @errorCode: 整型错误码，定义于 outerror.h 中的枚举或宏
 *
 * 该函数通过 switch 分支匹配预定义的错误码，
 * 将对应的错误消息输出到 stderr（标准错误流）。
 * 若错误码未识别，则输出未知错误码提示。
 */
void ErrorArg(int errorCode) {
	switch (errorCode) {
		/* 读取配置文件失败 */
		case ReadConfigFile:
			fprintf(stderr, "Error: Failed to read configuration file.\n");
			break;

		/* 切换工作目录失败 */
		case ChangeDir:
			fprintf(stderr, "Error: Unable to change directory.\n");
			break;

		/* 创建 .cpkg 目录失败（或目录不存在） */
		case CreateCpkgDir:
			fprintf(stderr, "Error: .cpkg directory not found.\n");
			break;

		/* 创建配置文件 JSON 文件失败 */
		case CreateConfigJsonFile:
			fprintf(stderr, "Error: Unable to create configuration JSON file.\n");
			break;

		/* 创建 libs 目录失败（或目录不存在） */
		case CreateLibsDir:
			fprintf(stderr, "Error: libs directory not found.\n");
			break;

		/* 指定的库文件不存在 */
		case LibNotExist:
			fprintf(stderr, "Error: Library file does not exist.\n");
			break;

		/* 创建 include 目录失败（或目录不存在） */
		case CreateIncludeDir:
			fprintf(stderr, "Error: include directory not found.\n");
			break;

		/* 指定的头文件不存在 */
		case IncludeNotExist:
			fprintf(stderr, "Error: Header file does not exist.\n");
			break;

		/* 压缩配置文件时出错（如 gzip 操作失败） */
		case GzipConfigFile:
			fprintf(stderr, "Error: Unable to compress configuration file.\n");
			break;

		/* 压缩 libs 和 include 目录（pocket 包）时出错 */
		case GzipPocketFile:
			fprintf(stderr, "Error: Unable to compress libs and include directories.\n");
			break;

		/* 解析配置文件格式失败（JSON 语法或结构错误） */
		case ParseConfigFormat:
			fprintf(stderr, "Error: Unable to parse configuration file format.\n");
			break;

		/* 创建最终输出文件（如 .cpkg 包文件）失败 */
		case CreateEndFile:
			fprintf(stderr, "Error: Unable to create final output file.\n");
			break;

		/* 未匹配到任何已知错误码，输出通用提示 */
		default:
			fprintf(stderr, "Unknown error code: %d\n", errorCode);
	}
}