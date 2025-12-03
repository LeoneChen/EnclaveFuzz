import sys
import subprocess
import re
import os


def process_address(address_string):
    # 使用正则表达式匹配模块名和地址偏移
    match = re.match(r"(.+)\+(0x[0-9a-fA-F]+)", address_string)
    if not match:
        print(f"Skipping invalid address format: {address_string}")
        return

    module_name = match.group(1)
    address_offset = match.group(2)
    address_offset = "%lx" % (int(address_offset, 16) - 4)

    # 构建并执行 addr2line 命令
    if os.path.isabs(module_name):
        command = [
            "llvm-addr2line-13",
            "-afCpe",
            module_name,
            address_offset,
        ]
        # print(command)
    else:
        print(f"Skipping unknown module: {module_name}")
        return

    # 使用 subprocess.run 来执行命令并捕获输出
    result = subprocess.run(command, capture_output=True, text=True, check=True)

    print(result.stdout.strip())


def main():
    """
    主函数，从命令行读取参数并循环处理。
    """
    # 检查命令行参数是否存在
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} [address1] [address2] ...")
        sys.exit(1)

    # sys.argv[0] 是脚本名，所以从 sys.argv[1] 开始是实际的参数
    addresses = sys.argv[1:]

    # 逐个处理每个地址
    for address in addresses:
        process_address(address)


if __name__ == "__main__":
    main()
