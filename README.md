# CGEncryptBreak
## 此例仅为学习交流之目的，未涉及核心的加密处理。
### 目标：分析创高App的登录加密协议，并实现脱机请求。
### 简述：通过静态分析，动态调试注入，抓包等方法，快速分析应用加密协议，此例仅为入门示例！
#### 抓包分析：
* 抓包工具：电脑上可使用charles、burp，手机上可使用thor，均支持https证书替换法抓包。
* 打开App，选择一个学校，账号密码均输入123，点击登录，查看请求的http包：
```
请求行:POST http://210.34.81.129/cgapp-server//api/f/v6/login? HTTP/1.1
请求体:password=EtCPK/NQZaOf8eDLJFtG/A%3D%3D&provinceCode=35&randomCode=34&username=123
请求头:
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-Hans-CN;q=1
Connection: close
Content-Length: 80
Content-Type: application/x-www-form-urlencoded
Host: 210.34.81.129
User-Agent: ChingoItemCGTY(Linux; iOS 12.1;iPhone HUUID/13FDADFB-0EF7-4BDE-9631-65F08BA6BC31)
app-key: azk3t4jrcfm5772t
sign: b3788046607f84e085eaeaac39b70c21
timestamp: 1553435930424
```
大致可以看出来，登录密码是加密过的，sign校验防止请求体被篡改，我们就着手研究这两处加密。
***
#### 使用静态分析分析App加密协议
* IDA是全球知名的反汇编工具，我们也可以使用Hopper进行静态分析，此处以IDA为例。
* 脱壳，解压ipa，找到.app文件，右键显示包内容，将其中的可执行mach-o文件导入IDA中。
* 在左侧Functions Window中搜索didFinishLaunchingWithOptions，寻找登录控制器。
* IDA可以直接F5生成C++风格的伪代码，大大减少了逐行分析汇编代码的时间。
1. 下方是[AppDelegate application:didFinishLaunchingWithOptions:]中的部分伪代码，为了方便查阅，作了一些删减。
```c++
bool __cdecl -[AppDelegate application:didFinishLaunchingWithOptions:](AppDelegate *self, SEL a2, id a3, id a4)
{
  //我们寻找根控制器是谁，经过查看发现当前函数中没有根控制器的赋值，双击对应函数，我们进入到可以函数[AppDelegate login]中：
  -[AppDelegate initLogin](v5, "initLogin");
  -[AppDelegate login](v5, "login");
} 
```
[AppDelegate login]中的伪代码
```c++
void __cdecl -[AppDelegate login](AppDelegate *self, SEL a2)
{
  //下面是Window的初始化，略过
  v2 = self;
  v3 = objc_msgSend(&OBJC_CLASS___UIWindow, "alloc");
  v4 = objc_msgSend(&OBJC_CLASS___UIScreen, "mainScreen");
  v5 = (void *)objc_retainAutoreleasedReturnValue(v4);
  objc_msgSend(v5, "bounds");
  v6 = objc_msgSend(v3, "initWithFrame:");
  -[AppDelegate setWindow:](v2, "setWindow:", v6);
  objc_release(v6);
  objc_release(v5);
  v7 = objc_msgSend(
         &OBJC_CLASS___UIColor,
         "colorWithRed:green:blue:alpha:",
         0.0431372549,
         0.670588235,
         0.996078431,
         1.0);
  v8 = objc_retainAutoreleasedReturnValue(v7);
  v9 = -[AppDelegate window](v2, "window");
  v10 = (void *)objc_retainAutoreleasedReturnValue(v9);
  objc_msgSend(v10, "setBackgroundColor:", v8);
  objc_release(v10);
  objc_release(v8);
  v11 = -[AppDelegate window](v2, "window");
  v12 = (void *)objc_retainAutoreleasedReturnValue(v11);
  objc_msgSend(v12, "makeKeyAndVisible");
  objc_release(v12);
  //取出了NSUserDefaults中key：oginNewVS7对应的value，并判断是否已登录
  v13 = objc_msgSend(&OBJC_CLASS___NSUserDefaults, "standardUserDefaults");
  v14 = (void *)objc_retainAutoreleasedReturnValue(v13);
  v15 = v14;
  v16 = objc_msgSend(v14, "valueForKey:", CFSTR("loginNewVS7"));
  v17 = (void *)objc_retainAutoreleasedReturnValue(v16);
  //判断取出的value是否等于“1”
  v18 = (unsigned __int64)objc_msgSend(v17, "isEqualToString:", CFSTR("1"));
  objc_release(v17);
  objc_release(v15);
  //如果等于“1”，则代表已登录，Window的根控制器是BaseTabBarVC
  if ( v18 )
  {
    v19 = objc_msgSend(&OBJC_CLASS___BaseTabBarVC, "alloc");
    v20 = objc_msgSend(v19, "init");
    v21 = -[AppDelegate window](v2, "window");
    v22 = (void *)objc_retainAutoreleasedReturnValue(v21);
    //回溯到上方，v20即为BaseTabBarVC对象
    objc_msgSend(v22, "setRootViewController:", v20);
    objc_release(v22);
    v23 = (XJTYWebLoginVC *)v20;
    //跳转到LABEL_10，releasev23
    goto LABEL_10;
  }
  v24 = +[GlobalActiveManger fetchTargetType](&OBJC_CLASS___GlobalActiveManger, "fetchTargetType");
  if ( v24 == (void *)3 )
  {
    //如果[GlobalActiveManger fetchTargetType] == 3
    //初始化XJTYWebLoginVC
    v33 = objc_msgSend(&OBJC_CLASS___XJTYWebLoginVC, "alloc");
    v34 = objc_msgSend(v33, "init");
    //初始化BaseNaviVC
    v35 = objc_msgSend(&OBJC_CLASS___BaseNaviVC, "alloc");
    //设置BaseNaviVC的RootViewController为XJTYWebLoginVC
    v36 = objc_msgSend(v35, "initWithRootViewController:", v34);
    v37 = -[AppDelegate window](v2, "window");
LABEL_9:
    v40 = (void *)objc_retainAutoreleasedReturnValue(v37);
    //设置AppWindow的根控制器为BaseNaviVC
    objc_msgSend(v40, "setRootViewController:", v36);
    objc_release(v40);
    objc_release(v36);
    v23 = v34;
    goto LABEL_10;
  }
  if ( v24 == (void *)2 )
  {
    //如果[GlobalActiveManger fetchTargetType] == 2
    //分析同上，此时Window的根控制器为BaseNaviVC，BaseNaviVC的根控制器为LoginVC
    v38 = objc_msgSend(&OBJC_CLASS___LoginVC, "alloc");
    v34 = objc_msgSend(v38, "init");
    v39 = objc_msgSend(&OBJC_CLASS___BaseNaviVC, "alloc");
    v36 = objc_msgSend(v39, "initWithRootViewController:", v34);
    v37 = -[AppDelegate window](v2, "window");
    goto LABEL_9;
  }
  if ( v24 != (void *)1 )
    return;
  v25 = objc_msgSend(&OBJC_CLASS___LoginVC, "alloc");
  v26 = objc_msgSend(v25, "init");
  v27 = objc_msgSend(&OBJC_CLASS___BaseNaviVC, "alloc");
  v28 = objc_msgSend(v27, "initWithRootViewController:", v26);
  v29 = objc_msgSend(&OBJC_CLASS___NSUserDefaults, "standardUserDefaults");
  v30 = (void *)objc_retainAutoreleasedReturnValue(v29);
  objc_msgSend(v30, "setObject:forKey:", CFSTR("0"), CFSTR("changeModel"));
  objc_release(v30);
  v31 = -[AppDelegate window](v2, "window");
  v32 = (void *)objc_retainAutoreleasedReturnValue(v31);
  objc_msgSend(v32, "setRootViewController:", v28);
  objc_release(v32);
  objc_release(v28);
  v23 = (XJTYWebLoginVC *)v26;
LABEL_10:
  objc_release(v23);
}
```
从上方的[AppDelegate login]中的伪代码我们可以清晰地看到App控制器的初始化流程：
* 取出了NSUserDefaults中key：oginNewVS7对应的value，如果为“1”，则代表已登录，设置Window的根控制器为BaseTabBarVC，并跳出这个函数。
* 若不为“1”，获取[GlobalActiveManger fetchTargetType]的值，如果为3，Window的根控制器为导航控制器BaseNaviVC，BaseNaviVC中的根控制器为XJTYWebLoginVC，同时跳出函数
* 若[GlobalActiveManger fetchTargetType]的值为2，此时Window的根控制器为BaseNaviVC，BaseNaviVC的根控制器为LoginVC，同时跳出函数。
* 若[GlobalActiveManger fetchTargetType]的值为1，此时Window的根控制器为BaseNaviVC，BaseNaviVC的根控制器为LoginVC，同时将NSUserDefaults中key为changeModel的value设置为0。
综上，我们需要寻找的登录控制器为LoginVC，下面我们加快速度。
2. 我们直接来到[LoginVC loginAction]方法。
```c++
void __cdecl -[LoginVC loginAction](LoginVC *self, SEL a2)
{
  v2 = self;
  v3 = -[LoginVC schoolMSModel](self, "schoolMSModel");
  v4 = (void *)objc_retainAutoreleasedReturnValue(v3);
  v5 = v4;
  v6 = objc_msgSend(v4, "loginType");
  v7 = (void *)objc_retainAutoreleasedReturnValue(v6);
  //如果LoginVC.schoolMSModel.loginType如果等于“3”
  if ( (unsigned int)objc_msgSend(v7, "isEqualToString:", CFSTR("3")) )
  {
    v8 = -[LoginVC infoView](v2, "infoView");
    v9 = (void *)objc_retainAutoreleasedReturnValue(v8);
    v10 = v9;
    v11 = objc_msgSend(v9, "inputInfoBackBoard");
    v12 = (void *)objc_retainAutoreleasedReturnValue(v11);
    v13 = (unsigned __int64)objc_msgSend(v12, "isHidden");
    objc_release(v12);
    objc_release(v10);
    objc_release(v7);
    objc_release(v5);
    //如果LoginVC.infoView.loginType.inputInfoBackBoard.isHidden == YES
    if ( v13 )
    {
      v14 = objc_msgSend(&OBJC_CLASS___WebLoginVC, "alloc");
      v15 = objc_msgSend(v14, "init");
      v16 = -[LoginVC schoolMSModel](v2, "schoolMSModel");
      v17 = objc_retainAutoreleasedReturnValue(v16);
      -[WebLoginVC setSchoolMSModel:](v15, "setSchoolMSModel:", v17);
      objc_release(v17);
      v18 = -[LoginVC schoolMSModel](v2, "schoolMSModel");
      v19 = (void *)objc_retainAutoreleasedReturnValue(v18);
      v20 = v19;
      v21 = objc_msgSend(v19, "loginUrl");
      v22 = objc_retainAutoreleasedReturnValue(v21);
      -[WebModuleVC setWebUrl:](v15, "setWebUrl:", v22);
      objc_release(v22);
      objc_release(v20);
      v23 = objc_msgSend(v2, "navigationController");
      v24 = (void *)objc_retainAutoreleasedReturnValue(v23);
      objc_msgSend(v24, "pushViewController:animated:", v15, 1LL);
      objc_release(v24);
      if ( __stack_chk_guard == v49 )
        objc_release(v15);
      return;
    }
  }
  else
  {
    objc_release(v7);
    objc_release(v5);
  }
  v25 = objc_msgSend(v2, "view");
  v26 = (void *)objc_retainAutoreleasedReturnValue(v25);
  objc_msgSend(v26, "endEditing:", 1LL);
  objc_release(v26);
  //如果[LoginVC checkLoginInfo] == YES 并且 [NetRequst checkNetworkState] == YES，大致可以看出是点击登录按钮之后进行的数据完整性，数据合法性和网络状态判定。
  if ( (unsigned int)-[LoginVC checkLoginInfo](v2, "checkLoginInfo")
    && (unsigned int)+[NetRequst checkNetworkState](&OBJC_CLASS___NetRequst, "checkNetworkState") )
  {
    //v27为当前密码输入框
    v27 = -[LoginInfoView passwordTextField](v2->_infoView, "passwordTextField");
    //mrc retain，可忽略，直接v28 = v27
    v28 = (void *)objc_retainAutoreleasedReturnValue(v27);
    v29 = v28;
    v30 = 当前输入的密码
    v30 = objc_msgSend(v28, "text");
    v31 = objc_retainAutoreleasedReturnValue(v30);
    v32 = v31;
    //我们可以清晰地看到，当前输入的密码被当做参数传入+[SecurityUtil encryptAESData:]中，返回加密后的data
    v33 = +[SecurityUtil encryptAESData:](&OBJC_CLASS___SecurityUtil, "encryptAESData:", v31);
    //v34即为加密后的data，从函数名可以看出，是aes加密
    v34 = objc_retainAutoreleasedReturnValue(v33);
    objc_release(v32);
    objc_release(v29);
    v45 = CFSTR("username");
    v35 = -[LoginInfoView userNameTextField](v2->_infoView, "userNameTextField");
    v36 = (void *)objc_retainAutoreleasedReturnValue(v35);
    v37 = v36;
    v38 = objc_msgSend(v36, "text");
    v39 = objc_retainAutoreleasedReturnValue(v38);
    v46 = CFSTR("password");
    v47 = v39;
    //加密后的data，通过函数+[SecurityUtil encodeBase64Data:]，转化为base64字符串
    v40 = +[SecurityUtil encodeBase64Data:](&OBJC_CLASS___SecurityUtil, "encodeBase64Data:", v34);
    v41 = objc_retainAutoreleasedReturnValue(v40);
    v48 = v41;
    v42 = objc_msgSend(&OBJC_CLASS___NSDictionary, "dictionaryWithObjects:forKeys:count:", &v47, &v45, 2LL);
    v43 = objc_retainAutoreleasedReturnValue(v42);
    objc_release(v41);
    objc_release(v39);
    objc_release(v37);
    v44 = objc_msgSend(v2, "class");
    objc_msgSend(v44, "cancelPreviousPerformRequestsWithTarget:selector:object:", v2, "loginRequstWithAdminInfo:", v43);
    //密码加密后，调用当前控制器的loginRequstWithAdminInfo:方法，提交登录处理
    objc_msgSend(v2, "performSelector:withObject:afterDelay:", "loginRequstWithAdminInfo:", v43, 0.300000012);
    objc_release(v43);
    objc_release(v34);
  }
}
```
* 从上方伪代码可以看出，密码通过+[SecurityUtil encryptAESData:]加密，返回的NSData对象通过+[SecurityUtil encodeBase64Data:]转为字符串，密码加密后，调用当前控制器的loginRequstWithAdminInfo:方法，提交登录处理。
3. 来到+[SecurityUtil encryptAESData:]中：
```c++
id __cdecl +[SecurityUtil encryptAESData:](SecurityUtil_meta *self, SEL a2, id a3)
{
  //调用传进来字符串的dataUsingEncoding:方法转化为NSData，对照系统NSStringEncoding枚举可以看出，参数4即为NSUTF8StringEncoding
  v3 = objc_msgSend(a3, "dataUsingEncoding:", 4LL);
  v4 = (void *)objc_retainAutoreleasedReturnValue(v3);
  v5 = v4;
  //调用NSData的AES256EncryptWithKey:方法，传入参数为6d3121b650e42855，一般就可以明确将密码进行了aes加密，并且key为6d3121b650e42855
  v6 = objc_msgSend(v4, "AES256EncryptWithKey:", CFSTR("6d3121b650e42855"));
  v7 = objc_retainAutoreleasedReturnValue(v6);
  objc_release(v5);
  return (id)objc_autoreleaseReturnValue(v7);
}
```
* 从上方伪代码可以看出，该函数调用NSData的AES256EncryptWithKey:方法，传入参数为6d3121b650e42855，一般就可以明确将密码进行了aes加密，并且key为6d3121b650e42855，为了保险起见，进入NSData的AES256EncryptWithKey:方法看看：
4. 来到[NSData AES256EncryptWithKey:]中：
```c++
id __cdecl -[NSData AES256EncryptWithKey:](NSData *self, SEL a2, id a3)
{
  NSData *v3; // x20
  char *v4; // x21
  void *v5; // x19
  void *v6; // x0
  void *v7; // x0
  id result; // x0
  void *v9; // x0
  __int64 v10; // [xsp+18h] [xbp-58h]
  __int128 v11; // [xsp+20h] [xbp-50h]
  __int128 v12; // [xsp+30h] [xbp-40h]
  char v13; // [xsp+40h] [xbp-30h]
  __int64 v14; // [xsp+48h] [xbp-28h]

  v3 = self;
  v13 = 0;
  v11 = 0u;
  v12 = 0u;
  objc_msgSend(a3, "getCString:maxLength:encoding:", &v11, 33LL, 4LL);
  v4 = (char *)objc_msgSend((void *)v3, "length");
  v5 = malloc((size_t)(v4 + 16));
  v10 = 0LL;
  v6 = (void *)objc_retainAutorelease(v3);
  v7 = objc_msgSend(v6, "bytes");
  //CCCrypt(0,0,3,&V11,16,0,[当前NSdata对象 bytes],[当前NSdata对象 length],malloc((size_t)(当前NSdata对象.length + 16)),&10)
  if ( (unsigned int)CCCrypt(0LL, 0LL, 3LL, &v11, 16LL, 0LL, v7, v4, v5, v4 + 16, &v10) )
  {
    free(v5);
    result = 0LL;
  }
  else
  {
    //若加密失败，将当前NSData转为字符串赋值给result
    v9 = objc_msgSend(&OBJC_CLASS___NSData, "dataWithBytesNoCopy:length:", v5, v10);
    result = (id)objc_retainAutoreleasedReturnValue(v9);
  }
  if ( __stack_chk_guard == v14 )
    result = (id)objc_autoreleaseReturnValue(result);
  return result;
}
```
* 从上方伪代码可以看出，CCCrypt为系统CommonCrypto中的加密类，第一个参数为0代表kCCEncrypt(加密)，第二个参数为0代表AES128，第三个参数为3代表kCCOptionPKCS7Padding|kCCOptionECBMode(1|2 = 3)，其他参数不再赘述了，因此可以确定，密码为AES128，ECB模式加密，无偏移量，加密key为6d3121b650e42855。
5.接着我们继续之前的步伐，来到LoginVC的loginRequstWithAdminInfo:方法中：
```c++
void __cdecl -[LoginVC loginRequstWithAdminInfo:](LoginVC *self, SEL a2, id a3)
{
  LoginVC *v3; // x19
  __int64 v4; // x22
  struct objc_object *v5; // x0
  __int64 v6; // x0
  SchoolMSModel *v7; // x0
  __int64 v8; // x21
  void **v9; // [xsp+8h] [xbp-48h]
  __int64 v10; // [xsp+10h] [xbp-40h]
  __int64 (__fastcall *v11)(); // [xsp+18h] [xbp-38h]
  void *v12; // [xsp+20h] [xbp-30h]
  LoginVC *v13; // [xsp+28h] [xbp-28h]

  v3 = self;
  v4 = objc_retain(a3, a2);
  v5 = +[CustomHUD showLoading:](&OBJC_CLASS___CustomHUD, "showLoading:", CFSTR("登录中...."));
  v6 = objc_retainAutoreleasedReturnValue(v5);
  objc_release(v6);
  v7 = -[LoginVC schoolMSModel](v3, "schoolMSModel");
  v8 = objc_retainAutoreleasedReturnValue(v7);
  v9 = _NSConcreteStackBlock;
  v10 = 3254779904LL;
  v11 = sub_10015D7CC;
  v12 = &unk_101024800;
  v13 = v3;
  //调用了+[LoginNet requstLoginWithAdminInfo:withSchoolIMSModel:success:failure:]
  +[LoginNet requstLoginWithAdminInfo:withSchoolIMSModel:success:failure:](
    &OBJC_CLASS___LoginNet,
    "requstLoginWithAdminInfo:withSchoolIMSModel:success:failure:",
    v4,
    v8,
    &v9,
    &off_101024850);
  objc_release(v4);
  objc_release(v8);
}
```
6. 来到+[LoginNet requstLoginWithAdminInfo:withSchoolIMSModel:success:failure:]：
```c++
void __cdecl +[LoginNet requstLoginWithAdminInfo:withSchoolIMSModel:success:failure:](LoginNet_meta *self, SEL a2, id a3, id a4, id a5, id a6)
{
  v6 = a6;
  v7 = a5;
  v8 = a4;
  v9 = a3;
  v10 = objc_retain(a3, a2);
  v12 = (void *)objc_retain(v8, v11);
  v14 = objc_retain(v7, v13);
  v16 = objc_retain(v6, v15);
  v17 = objc_msgSend(&OBJC_CLASS___NSBundle, "mainBundle");
  v18 = (void *)objc_retainAutoreleasedReturnValue(v17);
  v19 = v18;
  v20 = objc_msgSend(v18, "infoDictionary");
  v21 = (void *)objc_retainAutoreleasedReturnValue(v20);
  v22 = v21;
  v23 = objc_msgSend(v21, "objectForKey:", CFSTR("CFBundleVersion"));
  v24 = (void *)objc_retainAutoreleasedReturnValue(v23);
  objc_release(v22);
  objc_release(v19);
  v25 = objc_msgSend(v24, "intValue");
  v26 = objc_msgSend(&OBJC_CLASS___NSBundle, "mainBundle");
  v27 = (void *)objc_retainAutoreleasedReturnValue(v26);
  v28 = v27;
  v29 = objc_msgSend(v27, "infoDictionary");
  v30 = (void *)objc_retainAutoreleasedReturnValue(v29);
  v31 = v30;
  v32 = objc_msgSend(v30, "objectForKey:", CFSTR("CFBundleShortVersionString"));
  v33 = objc_retainAutoreleasedReturnValue(v32);
  v34 = v33;
  v35 = objc_msgSend(&OBJC_CLASS___NSString, "stringWithFormat:", CFSTR("%@.%d"), v33, v25);
  v36 = objc_retainAutoreleasedReturnValue(v35);
  objc_release(v34);
  objc_release(v31);
  objc_release(v28);
  v37 = objc_msgSend(&OBJC_CLASS___NSUserDefaults, "standardUserDefaults");
  v38 = (void *)objc_retainAutoreleasedReturnValue(v37);
  objc_msgSend(v38, "setValue:forKey:", v36, CFSTR("curVersion"));
  objc_release(v38);
  v39 = objc_msgSend(&OBJC_CLASS___NSString, "getAgent");
  v40 = objc_retainAutoreleasedReturnValue(v39);
  v41 = objc_msgSend(v9, "objectForKey:", CFSTR("username"));
  v42 = objc_retainAutoreleasedReturnValue(v41);
  v43 = objc_msgSend(v9, "objectForKey:", CFSTR("password"));
  v44 = objc_retainAutoreleasedReturnValue(v43);
  objc_release(v10);
  v45 = objc_msgSend(v12, "provinceCode");
  v46 = objc_retainAutoreleasedReturnValue(v45);
  v47 = objc_msgSend(v12, "randomCode");
  v48 = objc_retainAutoreleasedReturnValue(v47);
  v49 = v48;
  v50 = objc_msgSend(
          &OBJC_CLASS___NSDictionary,
          "dictionaryWithObjectsAndKeys:",
          v46,
          CFSTR("provinceCode"),
          v48,
          CFSTR("randomCode"),
          v42,
          CFSTR("username"),
          v44,
          CFSTR("password"),
          0LL);
  v51 = objc_retainAutoreleasedReturnValue(v50);
  objc_release(v49);
  objc_release(v46);
  //初始化NetManger单例
  v52 = +[NetManger shareManger](&OBJC_CLASS___NetManger, "shareManger");
  v53 = (void *)objc_retainAutoreleasedReturnValue(v52);
  v54 = objc_msgSend(v12, "serverUrl");
  v55 = objc_retainAutoreleasedReturnValue(v54);
  v69 = _NSConcreteStackBlock;
  v70 = 3254779904LL;
  v71 = sub_10017A730;
  v72 = &unk_101025F10;
  v73 = objc_retain(v16, v56);
  v74 = v12;
  v58 = objc_retain(v12, v57);
  v75 = v14;
  v64 = _NSConcreteStackBlock;
  v65 = 3254779904LL;
  v66 = sub_10017B084;
  v67 = &unk_101025F40;
  v60 = objc_retain(v14, v59);
  v68 = v73;
  v62 = objc_retain(v73, v61);
  LODWORD(v63) = 13.0;
  //调用NetManger的postWithRealmNameStr:parameters:withTimeoutInterval:isUseHttps:apiStr:success:failure:方法
  objc_msgSend(
    v53,
    "postWithRealmNameStr:parameters:withTimeoutInterval:isUseHttps:apiStr:success:failure:",
    v55,
    v51,
    1LL,
    CFSTR("/api/f/v6/login"),
    &v69,
    &v64,
    v63);
}
```
7. 来到NetManger的postWithRealmNameStr:parameters:withTimeoutInterval:isUseHttps:apiStr:success:failure:方法中：
```c++
// local variable allocation has failed, the output may be wrong!
void __cdecl -[NetManger postWithRealmNameStr:parameters:withTimeoutInterval:isUseHttps:apiStr:success:failure:](NetManger *self, SEL a2, id a3, id a4, float a5, bool a6, id a7, id a8, id a9)
{
  v9 = a9;
  v10 = a8;
  v11 = a7;
  v12 = a6;
  v13 = *(double *)&a5;
  v14 = a4;
  v15 = self;
  v16 = objc_retain(a3, a2);
  v18 = objc_retain(v14, v17);
  v20 = (void *)objc_retain(v11, v19);
  v22 = objc_retain(v10, v21);
  v24 = objc_retain(v9, v23);
  NSLog(CFSTR("%@"));
  v26 = objc_retain(qword_10134C9A0, v25);
  objc_sync_enter(v26);
  if ( objc_msgSend(v20, "rangeOfString:", CFSTR("/l/"), v16) == (void *)0x7FFFFFFFFFFFFFFFLL )
  {
    v60 = _NSConcreteStackBlock;
    v61 = 3254779904LL;
    v62 = sub_100160220;
    v63 = &unk_101024AB0;
    v64 = v15;
    v65 = objc_retain(v22, v27);
    v55 = _NSConcreteStackBlock;
    v56 = 3254779904LL;
    v57 = sub_1001602D0;
    v58 = &unk_101024AE0;
    v59 = objc_retain(v24, v28);
    //调用了+[RequstUtils postWithRealmNameStr:parameters:withTimeoutInterval:isUseHttps:apiStr:success:failure:]
    +[RequstUtils postWithRealmNameStr:parameters:withTimeoutInterval:isUseHttps:apiStr:success:failure:](
      &OBJC_CLASS___RequstUtils,
      "postWithRealmNameStr:parameters:withTimeoutInterval:isUseHttps:apiStr:success:failure:",
      v16,
      v18,
      v12,
      v20,
      &v60,
      &v55,
      v13);
    objc_release(v59);
    v29 = v65;
  }
  else
  {
    v30 = ((id (__cdecl *)(TokenUtils_meta *, SEL))objc_msgSend)((TokenUtils_meta *)&OBJC_CLASS___TokenUtils, "share");
    v31 = (void *)objc_retainAutoreleasedReturnValue(v30);
    v43 = _NSConcreteStackBlock;
    v44 = 3254779904LL;
    v45 = sub_1001602F4;
    v46 = &unk_101024B70;
    v47 = objc_retain(v16, v32);
    v48 = objc_retain(v18, v33);
    v53 = LODWORD(v13);
    v54 = v12;
    v49 = objc_retain(v20, v34);
    v50 = v15;
    v51 = objc_retain(v22, v35);
    v52 = objc_retain(v24, v36);
    v38 = _NSConcreteStackBlock;
    v39 = 3254779904LL;
    v40 = sub_100160570;
    v41 = &unk_101024BA0;
    v42 = objc_retain(v52, v37);
    objc_msgSend(v31, "checkTokenWithSuccess:failureToken:", &v43, &v38);
    objc_release(v31);
    objc_release(v42);
    objc_release(v52);
    objc_release(v51);
    objc_release(v49);
    objc_release(v48);
    v29 = v47;
  }
}
```
8. 来到[RequstUtils postWithRealmNameStr:parameters:withTimeoutInterval:isUseHttps:apiStr:success:failure:]方法：
```c++
void __cdecl +[RequstUtils postWithRealmNameStr:parameters:withTimeoutInterval:isUseHttps:apiStr:success:failure:](RequstUtils_meta *self, SEL a2, id a3, id a4, float a5, bool a6, id a7, id a8, id a9)
{
  v9 = a9;
  v10 = a8;
  v11 = a7;
  v12 = a5;
  v13 = a4;
  v14 = objc_retain(a3, a2);
  v16 = (void *)objc_retain(v13, v15);
  v18 = (void *)objc_retain(v11, v17);
  v109 = objc_retain(v10, v19);
  v110 = objc_retain(v9, v20);
  v21 = objc_msgSend(&OBJC_CLASS___NSString, "stringWithFormat:", CFSTR("%@%@?"), v14, v18);
  v22 = (void *)objc_retainAutoreleasedReturnValue(v21);
  objc_release(v14);
  v23 = objc_msgSend(v22, "stringByAddingPercentEscapesUsingEncoding:", 4LL);
  v24 = objc_retainAutoreleasedReturnValue(v23);
  objc_release(v22);
  v25 = objc_msgSend(&OBJC_CLASS___NSURL, "URLWithString:", v24);
  v26 = objc_retainAutoreleasedReturnValue(v25);
  v27 = v26;
  v28 = objc_msgSend(&OBJC_CLASS___NSMutableURLRequest, "requestWithURL:", v26);
  v29 = (void *)objc_retainAutoreleasedReturnValue(v28);
  objc_msgSend(v29, "setHTTPMethod:", CFSTR("POST"));
  v30 = +[AFHTTPSessionManager manager](&OBJC_CLASS___AFHTTPSessionManager, "manager");
  v31 = (void *)objc_retainAutoreleasedReturnValue(v30);
  v32 = v31;
  v33 = objc_msgSend(v31, "requestSerializer");
  v34 = (void *)objc_retainAutoreleasedReturnValue(v33);
  objc_msgSend(v34, "setStringEncoding:", 4LL);
  objc_release(v34);
  v35 = objc_msgSend(v18, "rangeOfString:", CFSTR("/l/"));
  v36 = objc_msgSend(v32, "requestSerializer");
  v37 = objc_retainAutoreleasedReturnValue(v36);
  
  if ( v35 == (void *)0x7FFFFFFFFFFFFFFFLL )
  {
    //如果apiStr中不包含/l/，此时为不需要token校验的url请求（0x7FFFFFFFFFFFFFFFLL即为2的63次方减一，为C++中Long的最大值，oc中NSNotFound = NSIntegerMax = LONG_MAX，因此此判断即为若[apiStr rangeOfString:@"/l/"] == NSNotFound）
    //调用+[BaseNetTool setHeadersWithoutToken:withParams:withSerializer:withSecret:]，也正是登录请求所调用的
    +[BaseNetTool setHeadersWithoutToken:withParams:withSerializer:withSecret:](
      &OBJC_CLASS___BaseNetTool,
      "setHeadersWithoutToken:withParams:withSerializer:withSecret:",
      v18,
      v16,
      v37,
      &stru_10106E9F0);
    objc_release(v37);
    v39 = v109;
    v38 = v110;
    v40 = v29;
    v41 = v24;
  }
  else
  {
    //此时为需要token校验的url请求
    v42 = v29;
    v43 = v24;
    v44 = +[GlobalActiveManger share](&OBJC_CLASS___GlobalActiveManger, "share");
    v45 = (void *)objc_retainAutoreleasedReturnValue(v44);
    v46 = v45;
    v47 = v27;
    v48 = objc_msgSend(v45, "authModel");
    v49 = (void *)objc_retainAutoreleasedReturnValue(v48);
    v50 = v49;
    v51 = objc_msgSend(v49, "secret");
    v52 = objc_retainAutoreleasedReturnValue(v51);
    v53 = +[GlobalActiveManger share](&OBJC_CLASS___GlobalActiveManger, "share");
    v54 = (void *)objc_retainAutoreleasedReturnValue(v53);
    v55 = v54;
    v56 = objc_msgSend(v54, "authModel");
    v57 = (void *)objc_retainAutoreleasedReturnValue(v56);
    v58 = v57;
    v59 = objc_msgSend(v57, "token");
    v60 = objc_retainAutoreleasedReturnValue(v59);
    +[BaseNetTool setHeadersWithAPiStr:withParams:withSerializer:withSecret:withtToken:](
      &OBJC_CLASS___BaseNetTool,
      "setHeadersWithAPiStr:withParams:withSerializer:withSecret:withtToken:",
      v18,
      v16,
      v37,
      v52,
      v60);
    v40 = v42;
    objc_release(v60);
    v27 = v47;
    objc_release(v58);
    v61 = v55;
    v41 = v43;
    objc_release(v61);
    v39 = v109;
    objc_release(v52);
    v62 = v50;
    v38 = v110;
    objc_release(v62);
    objc_release(v46);
    objc_release(v37);
  }
  v63 = objc_msgSend(v16, "mutableCopy");
  v64 = v63;
  v108 = v18;
  v111 = v63;
  if ( v63 && objc_msgSend(v63, "count") )
  {
    v105 = v40;
    v106 = v27;
    v107 = v41;
    v65 = objc_msgSend(v64, "allKeys");
    v66 = (void *)objc_retainAutoreleasedReturnValue(v65);
    v67 = "stringWithFormat:";
    if ( objc_msgSend(v66, "count") )
    {
      v68 = 0LL;
      do
      {
        v69 = objc_msgSend(v66, "objectAtIndexedSubscript:", v68);
        v70 = objc_retainAutoreleasedReturnValue(v69);
        v71 = v70;
        v72 = objc_msgSend(v16, "objectForKey:", v70);
        v73 = objc_retainAutoreleasedReturnValue(v72);
        v74 = v73;
        v75 = objc_msgSend(&OBJC_CLASS___NSString, v67, CFSTR("%@"), v73);
        v76 = (void *)objc_retainAutoreleasedReturnValue(v75);
        objc_release(v74);
        objc_release(v71);
        v77 = objc_msgSend(
                &OBJC_CLASS___NSCharacterSet,
                "characterSetWithCharactersInString:",
                CFSTR("#%<>[\\]^`{|}\"]+"));
        v78 = (void *)objc_retainAutoreleasedReturnValue(v77);
        v79 = v78;
        v80 = objc_msgSend(v78, "invertedSet");
        v81 = objc_retainAutoreleasedReturnValue(v80);
        v82 = v81;
        v83 = objc_msgSend(v76, "stringByAddingPercentEncodingWithAllowedCharacters:", v81);
        v84 = v67;
        v85 = v16;
        v86 = objc_retainAutoreleasedReturnValue(v83);
        objc_release(v76);
        objc_release(v82);
        objc_release(v79);
        v87 = objc_msgSend(v66, "objectAtIndexedSubscript:", v68);
        v88 = objc_retainAutoreleasedReturnValue(v87);
        objc_msgSend(v111, "setValue:forKey:", v86, v88);
        objc_release(v88);
        v89 = v86;
        v16 = v85;
        v67 = v84;
        objc_release(v89);
        ++v68;
      }
      while ( (unsigned __int64)objc_msgSend(v66, "count") > v68 );
    }
    objc_release(v66);
    v27 = v106;
    v41 = v107;
    v39 = v109;
    v38 = v110;
    v40 = v105;
  }
  v90 = objc_msgSend(v32, "requestSerializer");
  v91 = (void *)objc_retainAutoreleasedReturnValue(v90);
  objc_msgSend(v91, "setTimeoutInterval:", v12);
  objc_release(v91);
  v92 = objc_msgSend(
          &OBJC_CLASS___NSSet,
          "setWithObjects:",
          CFSTR("text/plain"),
          CFSTR("text/json"),
          CFSTR("application/json"),
          CFSTR("text/javascript"),
          CFSTR("text/html"),
          0LL);
  v93 = objc_retainAutoreleasedReturnValue(v92);
  v94 = objc_msgSend(v32, "responseSerializer");
  v95 = v40;
  v96 = (void *)objc_retainAutoreleasedReturnValue(v94);
  objc_msgSend(v96, "setAcceptableContentTypes:", v93);
  objc_release(v96);
  objc_release(v93);
  v97 = objc_msgSend(&OBJC_CLASS___NSMutableDictionary, "screeningEmptyValueDictionary:", v16);
  v98 = objc_retainAutoreleasedReturnValue(v97);
  v117 = _NSConcreteStackBlock;
  v118 = 3254779904LL;
  v119 = sub_1001949B4;
  v120 = &unk_1010270C0;
  v121 = v39;
  v112 = _NSConcreteStackBlock;
  v113 = 3254779904LL;
  v114 = sub_1001949DC;
  v115 = &unk_1010270F0;
  v100 = objc_retain(v39, v99);
  v116 = v38;
  v102 = objc_retain(v38, v101);
  v103 = objc_msgSend(v32, "POST:parameters:progress:success:failure:", v41, v98, &off_1010270A0, &v117, &v112);
  v104 = objc_retainAutoreleasedReturnValue(v103);
}
```
8. 我们来到 +[BaseNetTool setHeadersWithoutToken:withParams:withSerializer:withSecret:]：
```c++
void __cdecl +[BaseNetTool setHeadersWithoutToken:withParams:withSerializer:withSecret:](BaseNetTool_meta *self, SEL a2, id a3, id a4, id a5, id a6)
{
  v6 = a5;
  v7 = a4;
  //v8 = a3 = 当前接口名
  v8 = (void *)objc_retain(a3, a2);
  //v10 = v7 = a4 = 当前请求的字典
  v10 = objc_retain(v7, v9);
  v12 = (void *)objc_retain(v6, v11);
  v13 = objc_msgSend(&OBJC_CLASS___NSMutableDictionary, "screeningEmptyValueDictionary:", v10);
  v14 = objc_retainAutoreleasedReturnValue(v13);
  objc_release(v10);
  v15 = objc_msgSend(&OBJC_CLASS___NSDate, "date");
  v16 = (void *)objc_retainAutoreleasedReturnValue(v15);
  objc_msgSend(v16, "timeIntervalSince1970");
  //获取当前时间时间戳（毫秒）
  v18 = (unsigned __int64)(v17 * 1000.0);
  objc_release(v16);
  v19 = objc_msgSend(&OBJC_CLASS___NSString, "stringWithFormat:", CFSTR("%llu"), v18);
  //开始对传进来的post字典进行处理
  v20 = objc_retainAutoreleasedReturnValue(v19);
  v21 = objc_msgSend(&OBJC_CLASS___NSMutableDictionary, "screeningEmptyValueDictionary:", v14);
  v22 = objc_retainAutoreleasedReturnValue(v21);
  v23 = v22;
  v24 = objc_msgSend(&OBJC_CLASS___NSMutableDictionary, "getDictionarySorting:", v22);
  v25 = objc_retainAutoreleasedReturnValue(v24);
  v26 = v25;
  v27 = objc_msgSend(&OBJC_CLASS___NSArray, "getArrayConcatenationString:", v25);
  v28 = objc_retainAutoreleasedReturnValue(v27);
  ////v8 = a3 = 当前接口名
  if ( (unsigned __int64)objc_msgSend(v8, "isEqualToString:", CFSTR("/api/v2/weather")) & 1
    || (unsigned __int64)objc_msgSend(v8, "isEqualToString:", CFSTR("/api/v2/h5model/list")) & 1
    || (unsigned __int64)objc_msgSend(v8, "isEqualToString:", CFSTR("/api/school")) & 1
    || (unsigned __int64)objc_msgSend(v8, "isEqualToString:", CFSTR("/api/v2/school/detail")) & 1
    || (unsigned __int64)objc_msgSend(v8, "isEqualToString:", CFSTR("/api/getRoute")) & 1
    || (unsigned __int64)objc_msgSend(v8, "isEqualToString:", CFSTR("/api/feedback")) & 1
    || (unsigned __int64)objc_msgSend(v8, "isEqualToString:", CFSTR("/api/version")) & 1
    || (unsigned __int64)objc_msgSend(v8, "isEqualToString:", CFSTR("/api/feedback/list")) & 1
    || (unsigned int)objc_msgSend(v8, "isEqualToString:", CFSTR("/api/v2/phoneset")) )
  {
    //如果接口名为上方的其中一种
    v29 = objc_msgSend(
            &OBJC_CLASS___NSString,
            "stringWithFormat:",
            CFSTR("%@%@%@%@ %@"),
            CFSTR("6d3121b650e42855976d0f70dd2048e4"),
            v8,
            v28,
            v20,
            CFSTR("6d3121b650e42855976d0f70dd2048e4"));
    v30 = (void *)objc_retainAutoreleasedReturnValue(v29);
    v31 = v30;
    v32 = objc_msgSend(v30, "md5String");
    v33 = objc_retainAutoreleasedReturnValue(v32);
    objc_msgSend(v12, "setValue:forHTTPHeaderField:", v33, CFSTR("sign"));
    objc_release(v33);
    v34 = CFSTR("cgsoft");
  }
  else
  {
  //显然，登录接口在这里处理，V8为当前接口名/api/v6/login，v28为当前post字典转成的字符串，v20为当前的时间戳
    v37 = objc_msgSend(
            &OBJC_CLASS___NSString,
            "stringWithFormat:",
            CFSTR("%@%@%@%@ %@"),
            CFSTR("262b6c001ea05beceb9d560be1dbf14f"),
            v8,
            v28,
            v20,
            CFSTR("262b6c001ea05beceb9d560be1dbf14f"));
    v38 = (void *)objc_retainAutoreleasedReturnValue(v37);
    v31 = v38;
    v39 = objc_msgSend(v38, "md5String");
    v40 = objc_retainAutoreleasedReturnValue(v39);
    objc_msgSend(v12, "setValue:forHTTPHeaderField:", v40, CFSTR("sign"));
    objc_release(v40);
    v34 = CFSTR("azk3t4jrcfm5772t");
  }
  //可见app-key是常量字符串azk3t4jrcfm5772t
  objc_msgSend(v12, "setValue:forHTTPHeaderField:", v34, CFSTR("app-key"));
  objc_release(v31);
  v35 = objc_msgSend(&OBJC_CLASS___NSString, "getAgent");
  v36 = objc_retainAutoreleasedReturnValue(v35);
  objc_msgSend(v12, "setValue:forHTTPHeaderField:", v36, CFSTR("User-Agent"));
  objc_release(v36);
  objc_msgSend(v12, "setValue:forHTTPHeaderField:", v20, CFSTR("timestamp"));
}
```
* 从上方伪代码可以看出，sign校验通过"262b6c001ea05beceb9d560be1dbf14f"+/api/v6/login+post字典转为的字符串+时间戳+" "+"262b6c001ea05beceb9d560be1dbf14f"的方式拼接，最终进行md5加密生成，那接下来就是寻找post字典是如何转为字符串的。
9. +[NSMutableDictionary screeningEmptyValueDictionary:]用于去除字典中的空元素，+[NSMutableDictionary getDictionarySorting:]用于字典中key按照ASCLL排序，+[NSArray getArrayConcatenationString:]用于将字典转化为keyvalue的形式，形如username123pwd123，具体分析过程同上。

10. 至此，完整的静态分析过程结束，之后就可以依据上方分析结果使用其他语言脱机请求了。
*** 
#### 动态分析，基于[ZXHookUtil](https://github.com/SmileZXLee/ZXHookUtil)
1. 我们添加一个全局按钮，并且在按钮点击事件中打印当前控制器，来到登录控制器，点击按钮，即可观察到登录控制器类名：
```objective-c
dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [ZXHookUtil addBtnCallBack:^(UIButton *button) {
            UIViewController *loginVC = [ZXHookUtil getTopVC];
            NSLog(@"TopVC:%@",loginVC);
        }];
    });

```
2. 添加类和方法追踪，具体需要对哪些类和方法添加追踪需要结合上方的静态分析：
```objective-c
[ZXHookUtil addClassTrace:@"LoginVC"];
[ZXHookUtil addClassTrace:@"SecurityUtil"];
[ZXHookUtil addClassTrace:@"NSData" methodList:@[@"AES256EncryptWithKey:"]];
[ZXHookUtil addClassTrace:@"LoginNet"];
[ZXHookUtil addClassTrace:@"NetManger"];
[ZXHookUtil addClassTrace:@"RequstUtils"];
[ZXHookUtil addClassTrace:@"BaseNetTool"];
[ZXHookUtil addClassTrace:@"NSMutableDictionary" methodList:@[@"screeningEmptyValueDictionary:",@"getDictionarySorting:"]];
[ZXHookUtil addClassTrace:@"NSArray" methodList:@[@"getArrayConcatenationString:"]];
[ZXHookUtil addClassTrace:@"NSString" methodList:@[@"md5String"]];

```
3. 打印方法调用层级：
```objective-c
[ZXMethodLog][02:07:56.344189047] ┌ -[Call][<LoginVC: 0x15be83c50> loginAction]
[ZXMethodLog][02:07:56.344745039] │ ┌ -[Call][<LoginVC: 0x15be83c50> schoolMSModel]
[ZXMethodLog][02:07:56.345129013] │ └ -[Return]<SchoolMSModel: 0x17010beb0>
[ZXMethodLog][02:07:56.391180038] │ ┌ -[Call][<LoginVC: 0x15be83c50> checkLoginInfo]
[ZXMethodLog][02:07:56.391563057] │ └ -[Return]1
[ZXMethodLog][02:07:56.393897056] │ ┌ +[Call][SecurityUtil encryptAESData:123]
[ZXMethodLog][02:07:56.394659042] │ │ ┌ +[Call][<313233> AES256EncryptWithKey:6d3121b650e42855]
[ZXMethodLog][02:07:56.395189046] │ │ └ +[Return]<12d08f2b f35065a3 9ff1e0cb 245b46fc>
[ZXMethodLog][02:07:56.395439982] │ └ +[Return]<12d08f2b f35065a3 9ff1e0cb 245b46fc>
[ZXMethodLog][02:07:56.396046042] │ ┌ +[Call][SecurityUtil encodeBase64Data:<12d08f2b f35065a3 9ff1e0cb 245b46fc>]
[ZXMethodLog][02:07:56.396507024] │ └ +[Return]EtCPK/NQZaOf8eDLJFtG/A==
[ZXMethodLog][02:07:56.396796941] └ -[Return]void
[ZXMethodLog][02:07:56.699197053] ┌ -[Call][<LoginVC: 0x15be83c50> loginRequstWithAdminInfo:<__NSDictionaryI: 0x174671540 JsonContent: {"username" : "123","password" : "EtCPK\/NQZaOf8eDLJFtG\/A=="}>]
[ZXMethodLog][02:07:56.723934054] │ ┌ -[Call][<LoginVC: 0x15be83c50> schoolMSModel]
[ZXMethodLog][02:07:56.724174976] │ └ -[Return]<SchoolMSModel: 0x17010beb0>
[ZXMethodLog][02:07:56.725550055] │ ┌ +[Call][LoginNet requstLoginWithAdminInfo:<__NSDictionaryI: 0x174671540 JsonContent: {"username" : "123","password" : "EtCPK\/NQZaOf8eDLJFtG\/A=="}> withSchoolIMSModel:<SchoolMSModel: 0x17010beb0> success:unknown failure:unknown]
[ZXMethodLog][02:07:56.730767965] │ │ ┌ +[Call][NetManger shareManger]
[ZXMethodLog][02:07:56.731011986] │ │ └ +[Return]<NetManger: 0x1700050a0>
[ZXMethodLog][02:07:56.731948018] │ │ ┌ -[Call][<NetManger: 0x1700050a0> postWithRealmNameStr:http://210.34.81.129/cgapp-server/ parameters:<__NSDictionaryI: 0x1740fec00 JsonContent: {"username" : "123","provinceCode" : "35","password" : "EtCPK\/NQZaOf8eDLJFtG\/A==","randomCode" : "34"}> withTimeoutInterval:13 isUseHttps:1 apiStr:/api/f/v6/login success:unknown failure:unknown]
[ZXMethodLog][02:07:56.734148025] │ │ │ ┌ +[Call][RequstUtils postWithRealmNameStr:http://210.34.81.129/cgapp-server/ parameters:<__NSDictionaryI: 0x1740fec00 JsonContent: {"username" : "123","provinceCode" : "35","password" : "EtCPK\/NQZaOf8eDLJFtG\/A==","randomCode" : "34"}> withTimeoutInterval:13 isUseHttps:1 apiStr:/api/f/v6/login success:unknown failure:unknown]
[ZXMethodLog][02:07:56.737403988] │ │ │ │ ┌ +[Call][BaseNetTool setHeadersWithoutToken:/api/f/v6/login withParams:<__NSDictionaryI: 0x1740fec00 JsonContent: {"username" : "123","provinceCode" : "35","password" : "EtCPK\/NQZaOf8eDLJFtG\/A==","randomCode" : "34"}> withSerializer:<AFHTTPRequestSerializer: 0x1742a13e0> withSecret:]
[ZXMethodLog][02:07:56.738083004] │ │ │ │ │ ┌ +[Call][NSMutableDictionary screeningEmptyValueDictionary:<__NSDictionaryI: 0x1740fec00 JsonContent: {"username" : "123","provinceCode" : "35","password" : "EtCPK\/NQZaOf8eDLJFtG\/A==","randomCode" : "34"}>]
[ZXMethodLog][02:07:56.738473057] │ │ │ │ │ └ +[Return]<__NSDictionaryM: 0x1744412c0 JsonContent: {"username" : "123","provinceCode" : "35","password" : "EtCPK\/NQZaOf8eDLJFtG\/A==","randomCode" : "34"}>
[ZXMethodLog][02:07:56.738937020] │ │ │ │ │ ┌ +[Call][NSMutableDictionary screeningEmptyValueDictionary:<__NSDictionaryM: 0x1744412c0 JsonContent: {"username" : "123","provinceCode" : "35","password" : "EtCPK\/NQZaOf8eDLJFtG\/A==","randomCode" : "34"}>]
[ZXMethodLog][02:07:56.740399956] │ │ │ │ │ └ +[Return]<__NSDictionaryM: 0x17045e480 JsonContent: {"username" : "123","provinceCode" : "35","password" : "EtCPK\/NQZaOf8eDLJFtG\/A==","randomCode" : "34"}>
[ZXMethodLog][02:07:56.741129994] │ │ │ │ │ ┌ +[Call][NSMutableDictionary getDictionarySorting:<__NSDictionaryM: 0x17045e480 JsonContent: {"username" : "123","provinceCode" : "35","password" : "EtCPK\/NQZaOf8eDLJFtG\/A==","randomCode" : "34"}>]
[ZXMethodLog][02:07:56.742100954] │ │ │ │ │ └ +[Return]({password = "EtCPK/NQZaOf8eDLJFtG/A==";},{provinceCode = 35;},{randomCode = 34;},{username = 123;})
[ZXMethodLog][02:07:56.743304014] │ │ │ │ │ ┌ +[Call][NSArray getArrayConcatenationString:({password = "EtCPK/NQZaOf8eDLJFtG/A==";},{provinceCode = 35;},{randomCode = 34;},{username = 123;})]
[ZXMethodLog][02:07:56.743759989] │ │ │ │ │ └ +[Return]passwordEtCPK/NQZaOf8eDLJFtG/A==provinceCode35randomCode34username123
[ZXMethodLog][02:07:56.744313955] │ │ │ │ │ ┌ +[Call][262b6c001ea05beceb9d560be1dbf14f/api/f/v6/loginpasswordEtCPK/NQZaOf8eDLJFtG/A==provinceCode35randomCode34username1231553450876738 262b6c001ea05beceb9d560be1dbf14f md5String]
[ZXMethodLog][02:07:56.744688987] │ │ │ │ │ └ +[Return]a3f30d14d2305a489b5bb63745207d7a
[ZXMethodLog][02:07:56.747871041] │ │ │ │ └ +[Return]void
[ZXMethodLog][02:07:56.748824000] │ │ │ │ ┌ +[Call][NSMutableDictionary screeningEmptyValueDictionary:<__NSDictionaryI: 0x1740fec00 JsonContent: {"username" : "123","provinceCode" : "35","password" : "EtCPK\/NQZaOf8eDLJFtG\/A==","randomCode" : "34"}>]
[ZXMethodLog][02:07:56.749119997] │ │ │ │ └ +[Return]<__NSDictionaryM: 0x170241ad0 JsonContent: {"username" : "123","provinceCode" : "35","password" : "EtCPK\/NQZaOf8eDLJFtG\/A==","randomCode" : "34"}>
[ZXMethodLog][02:07:56.751389980] │ │ │ └ +[Return]void
[ZXMethodLog][02:07:56.751531958] │ │ └ -[Return]void
[ZXMethodLog][02:07:56.751754045] │ └ +[Return]void
[ZXMethodLog][02:07:56.751883983] └ -[Return]void
[ZXMethodLog][02:07:57.928156971] ┌ -[Call][<NetManger: 0x1700050a0> checkStatus:<__NSDictionaryI: 0x17086b2c0 JsonContent: {"message" : "用户名或密码错误","data" : {  },"code" : 420}>]
[ZXMethodLog][02:07:57.928491950] └ -[Return]1

```

#### 最终，我们使用python验证上方的分析，成功登录并获取token和secret。
![DemoImg](https://github.com/SmileZXLee/CGEncryptBreak/blob/master/DemoImg/cgDemoImg.png?raw=true)  





