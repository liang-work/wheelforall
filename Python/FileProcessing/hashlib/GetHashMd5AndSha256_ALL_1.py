"""
By: liang-work
基于hashlib进行md5和sha256摘要计算
"""
import hashlib

def md5_text(t:str):
    """
    计算字符串的md5值
    :param t: 字符串
    :return: md5值
    """
    h = hashlib.md5()
    h.update(t.encode("utf-8"))
    return h.hexdigest()

def sha256_text(t:str):
    """
    计算字符串的sha256值
    :param t: 字符串
    :return: sha256值
    """
    h = hashlib.sha256()
    h.update(t.encode("utf-8"))
    return h.hexdigest()

def md5_file(path):
    """
    计算文件的md5值
    :param path: 文件路径
    :return: md5值
    """
    with open(path, 'rb') as file:
        t = file.read()
    h = hashlib.md5()
    h.update(t.encode("utf-8"))
    return h.hexdigest()

def sha256_file(path):
    """
    计算文件的sha256值
    :param path: 文件路径
    :return: sha256值
    """
    with open(path, 'rb') as file:
        t = file.read()
    h = hashlib.sha256()
    h.update(t.encode("utf-8"))
    return h.hexdigest()

def check_file(file_path,hash_md5,hash_sha256):
    """
    检查文件的md5和sha256值是否与给定值相等
    :param file_path: 文件路径
    :param hash_md5: 给定的md5值
    :param hash_sha256: 给定的sha256值
    :return: 如果文件的md5和sha256值与给定值相等，则返回True，否则返回False
    """
    return md5_file(path=file_path) == hash_md5 and sha256_file(path=file_path) == hash_sha256