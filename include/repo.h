/* repo.h - simple remote repository support for cpkg
 */
#ifndef REPO_H
#define REPO_H

/* 在远程索引中搜索关键字并打印匹配结果 */
int repo_search(const char *query);

/* 根据包名从远程仓库下载包到指定文件路径（覆盖） */
int repo_fetch_package_by_name(const char *name, const char *dest_path);

/* 下载并直接安装包（下载到临时并调用 install_package） */
int repo_install_by_name(const char *name);

#endif /* REPO_H */
