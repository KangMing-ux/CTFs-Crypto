比赛网址：[WMCTF2020](https://adworld.xctf.org.cn/match/contest_challenge?event=146&hash=684a58cc-1140-4937-99f2-ef347d777d9f.event)

# 一、piece_of_cake

## 1. 题目信息
附件是一个py脚本，[GitHub备份](https://github.com/KangMing-ux/CTFs-Crypto/tree/master/WMCTF2020/piece_of_cake)中的task.py。

## 2. 分析

eat_cake函数中的各个变量的定义如下：

* $p,q$为512位随机素数，$ph=(p-1) \cdot (q+1),N=p \cdot q,d=e^{-1}\ \textrm{mod}\ ph$

* $cake$为768位随机素数，$q$重新赋值为1536位随机素数，将$d$的值赋给$f$，$g$为随机素数，$g$的位数等于$q$的位数减去$f$的位数再减去1

* $h=f^{-1} \cdot g\ \textrm{mod}\ q$，$r$为512位随机素数，$c=(r \cdot h+cake)\ \textrm{mod}\ q$

由$h=f^{-1} \cdot g\ \textrm{mod}\ q$可得$f \cdot h \equiv g\ \textrm{mod}\ q$，记为$f \cdot h-t \cdot q=g$，构造矩阵
$$
M=\begin{pmatrix}
1 & h\\
0 & q
\end{pmatrix}
$$
则有
$$
\begin{pmatrix}
f & -t
\end{pmatrix} \cdot \begin{pmatrix}
1 & h\\
0 & q
\end{pmatrix} = \begin{pmatrix}
f & g
\end{pmatrix}
$$
则$
\begin{pmatrix}
f & g
\end{pmatrix}
$是格$L(M)$上的短格基，因此有可能可使用LLL算法或BKZ算法求出，这里说有可能求出，因为在解题时并不是每次都能找到短格基$
\begin{pmatrix}
f & g
\end{pmatrix}
$
假设我们求出的短格基为$
\begin{pmatrix}
f & g
\end{pmatrix}
$，再由公式$c=(r \cdot h+cake)\ \textrm{mod}\ q$

则

$f \cdot c \equiv f \cdot (r \cdot h+cake) \equiv (r \cdot g+f \cdot cake)\ \textrm{mod}\ q$

从而

$(r \cdot g+f \cdot cake)= f \cdot c\ \textrm{mod}\ q$

两边模$g$可得

$f \cdot cake \equiv (f \cdot c\ \textrm{mod}\ q)\ \textrm{mod}\ g$

于是

$cake=f^{-1} \cdot (f \cdot c\ \textrm{mod}\ q)\ \textrm{mod}\ g$

注意，上面等式中$f^{-1}$是$f$在$g$下的逆，不能与括号内的$f$抵消。

## 3. 解题

上述链接中的solve.sage为解题的sage脚本。

## 4. 备注

此exp并不能保证次次成功！不过它的有效性不可否认，上述链接中的test.sage即可验证。

以下是我对test.sage四次的运行结果：

```Bash
$ sage test.sage
success! 48 -th
$ sage test.sage
success! 2 -th
$ sage test.sage
success! 50 -th
$ sage test.sage
success! 24 -th
```

从而验证了解题脚本solve.sage的有效性。

# 二、babySum

## 1. 题目信息

附件是两个py脚本与一个json文件，[GitHub备份](https://github.com/KangMing-ux/CTFs-Crypto/tree/master/WMCTF2020/babySum)中的task.py与check.py。

## 2. 分析

task.py告诉我们生成data中数据的逻辑，其实很好理解：生成$n=120$个150位的随机数，组成数组$A$，从中选$k=20$个相加生成和$s$；

记数组$A=[a_{1},\cdots,a_{n}]$，check.py读入120个数$b_{1},\cdots,b_{n}(b_{i}={0,1})$，其中20个为1，另外100个为1，检验$\sum_{i=1}^{n}a_{i} \cdot b_{i}=s$，如果等式成立，就打印出flag。

到这里我们共有3个约束条件：
* $\sum_{i=1}^{n}b_{i}=k$
* $\sum_{i=1}^{n}a_{i} \cdot b_{i}=s$
* $b_{i}=0,1;i=1,\cdots,n$

遇到这种问题一般转化为格基约减问题，构造矩阵$
\begin{pmatrix}
1 &   &   &   & a_{1} & 1 \\
  & 1 &   &   & a_{2} & 1 \\
  &   &\ddots &   &\vdots &\vdots \\
  &   &   & 1 & a_{n} & 1 \\
  &   &   &   & -s & -k &
\end{pmatrix}=M
$

那么$
\begin{pmatrix}
b_{1} & b_{2} & \cdots & b_{n} & 1
\end{pmatrix} \cdot M=\begin{pmatrix}
b_{1} & b_{2} & \cdots & b_{n} & 0 & 0
\end{pmatrix}
$

即通过格基约减可以求出$b_{1},\cdots,b_{n}$。

理想很丰满，现实很骨感！

约减后的格基无法达到我们需要的结果！直到看到writeup，这里需要记住一个很有用的技巧，可类比约束优化问题对约束条件的处理，当不满足约束条件$\begin{cases}
\sum_{i=1}^{n}b_{i}=k\\
\sum_{i=1}^{n}a_{i} \cdot b_{i}=s
\end{cases}
$时加大“惩罚”，我们重新设计格基矩阵$M$为$
\begin{pmatrix}
1 &   &   &   & N \cdot a_{1} & N \\
  & 1 &   &   & N \cdot a_{2} & N \\
  &   &\ddots &   &\vdots &\vdots \\
  &   &   & 1 & N \cdot a_{n} & N \\
  &   &   &   & -N \cdot s & -N \cdot k &
\end{pmatrix}
$
其中$N=[\sqrt{n}]，$
此时仍然有$
\begin{pmatrix}
b_{1} & b_{2} & \cdots & b_{n} & 1
\end{pmatrix} \cdot M=\begin{pmatrix}
b_{1} & b_{2} & \cdots & b_{n} & 0 & 0
\end{pmatrix}
$

然后就是比较玄学的问题，对同一格，改变格基矩阵行的顺序，约减的结果也会不同，官方的writeup就是不断打乱格基矩阵的行，然后进行格基约减；再就是为了更快得到结果，需要进行多线程编程；上述链接中的solve.sage为解题的sage脚本；官方设置的8个线程，我自己改成6个线程，跑了几次，基本上都是20分钟左右出结果。

```Bash
$ sage solve.sage   
(0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0)
cost time:  0:25:27
```
