// 旧CCSupport热刷新通知在新系统调用已移除的方法；安装末尾统一由sbreload刷新。
// 保留兼容入口但不再发送该通知，避免旧安装脚本调用时触发安全模式。
int main(void){return 0;}
