# AI-Sense  AI 对敏感文件自动识别之模型准确率提升-先知社区

> **来源**: https://xz.aliyun.com/news/17223  
> **文章ID**: 17223

---

# AI-Sense AI 对敏感文件自动识别之模型准确率提升

## 前言

我们之前已经把大框架完成了，但是对于AI的精准率我们还需要去训练提高，下面会详细介绍一下训练的基础和如何根据敏感文件的训练，提高AI对敏感的识别度和准确率

​

## 训练过程

给出我的代码

```
import torch
import torch.nn as nn
import torch.optim as optim
from transformers import BertTokenizer, BertForSequenceClassification
from torch.utils.data import DataLoader, Dataset
from sklearn.model_selection import train_test_split
import os
import glob
import pandas as pd
from tqdm import tqdm
from cryptography.fernet import Fernet

# 选择设备
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# 生成密钥
key = Fernet.generate_key()
cipher_suite = Fernet(key)


# 数据加密、解密和脱敏处理
def encrypt_code(code):
    return cipher_suite.encrypt(code.encode()).decode()


def decrypt_code(encrypted_code):
    return cipher_suite.decrypt(encrypted_code.encode()).decode()


def desensitize_code(code):
    return code.replace("os.system", "os.system_placeholder")


# 读取和预处理数据
def load_data(data_path):
    csv_files = glob.glob(data_path)
    data_list = [pd.read_csv(file) for file in csv_files]
    data = pd.concat(data_list, ignore_index=True)
    if 'code' not in data.columns or 'label' not in data.columns:
        raise ValueError("数据集必须包含 'code' 和 'label' 列！")
    data['code'] = data['code'].astype(str)
    data['encrypted_code'] = data['code'].apply(encrypt_code)
    data['desensitized_code'] = data['code'].apply(desensitize_code)
    return data['desensitized_code'], data['label']


# 自定义数据集类
class CodeDataset(Dataset):
    def __init__(self, texts, labels, tokenizer, max_len=128):
        self.texts = texts.tolist()
        self.labels = labels.tolist()
        self.tokenizer = tokenizer
        self.max_len = max_len

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        encoding = self.tokenizer(
            self.texts[idx],
            padding="max_length",
            truncation=True,
            max_length=self.max_len,
            return_tensors="pt"
        )
        return {key: val.squeeze(0) for key, val in encoding.items()}, torch.tensor(self.labels[idx])


# 训练模型
def train(model, train_loader, optimizer, criterion, device, epochs=3, model_path="models/model.pth"):
    model.train()
    for epoch in range(epochs):
        total_loss, total_correct = 0, 0
        for batch in tqdm(train_loader, desc=f"训练 Epoch {epoch + 1}"):
            inputs, labels = batch
            inputs = {key: val.to(device) for key, val in inputs.items()}
            labels = labels.to(device)

            optimizer.zero_grad()
            outputs = model(**inputs)
            loss = criterion(outputs.logits, labels)
            loss.backward()
            optimizer.step()

            total_loss += loss.item()
            total_correct += (outputs.logits.argmax(dim=1) == labels).sum().item()

        accuracy = total_correct / len(train_loader.dataset)
        print(f"✅ Epoch {epoch + 1}: Loss = {total_loss:.4f}, Accuracy = {accuracy:.4f}")

    torch.save(model.state_dict(), model_path)

    print(f"✅ 模型已保存到 {model_path}")


# 评估模型
def evaluate(model, test_loader, device):
    model.eval()
    total_correct = 0
    with torch.no_grad():
        for batch in tqdm(test_loader, desc="评估"):
            inputs, labels = batch
            inputs = {key: val.to(device) for key, val in inputs.items()}
            labels = labels.to(device)
            outputs = model(**inputs)
            total_correct += (outputs.logits.argmax(dim=1) == labels).sum().item()
    accuracy = total_correct / len(test_loader.dataset)
    print(f"📊 测试集准确率: {accuracy:.4f}")


# 主程序
if __name__ == "__main__":
    data_path = "1.csv"
    model_path = "AI/model/model.pth"
    X, y = load_data(data_path)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.1, random_state=42)
    tokenizer = BertTokenizer.from_pretrained("bert-base-uncased")

    train_dataset = CodeDataset(X_train, y_train, tokenizer)
    test_dataset = CodeDataset(X_test, y_test, tokenizer)

    train_loader = DataLoader(train_dataset, batch_size=16, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=16)

    model = BertForSequenceClassification.from_pretrained("bert-base-uncased", num_labels=len(set(y_train)))
    if os.path.exists(model_path):
        print("🔄 加载已有模型，继续训练...")
        model.load_state_dict(torch.load(model_path, map_location=device))
    model.to(device)
    optimizer = optim.AdamW(model.parameters(), lr=2e-5)
    criterion = nn.CrossEntropyLoss()

    train(model, train_loader, optimizer, criterion, device, epochs=3, model_path=model_path)
    evaluate(model, test_loader, device)

```

## 训练方法

主要聚焦于我们的

```
# 训练模型
def train(model, train_loader, optimizer, criterion, device, epochs=3, model_path="models/model.pth"):
    model.train()
    for epoch in range(epochs):
        total_loss, total_correct = 0, 0
        for batch in tqdm(train_loader, desc=f"训练 Epoch {epoch + 1}"):
            inputs, labels = batch
            inputs = {key: val.to(device) for key, val in inputs.items()}
            labels = labels.to(device)

            optimizer.zero_grad()
            outputs = model(**inputs)
            loss = criterion(outputs.logits, labels)
            loss.backward()
            optimizer.step()

            total_loss += loss.item()
            total_correct += (outputs.logits.argmax(dim=1) == labels).sum().item()

        accuracy = total_correct / len(train_loader.dataset)
        print(f"✅ Epoch {epoch + 1}: Loss = {total_loss:.4f}, Accuracy = {accuracy:.4f}")

    torch.save(model, model_path)
    print(f"✅ 模型已保存到 {model_path}")

```

### 前向传播

这个是比较难理解的，特点就是返回预测值

前向传播是神经网络从输入到输出的计算过程，核心目的是生成预测值（logits）

大概处理就是

输入数据处理  
通过 Transformer 计算特征  
分类头（Fully Connected 层）计算 logits  
返回 logits 作为预测值

```
batch = {
    "input_ids": torch.tensor([[101, 2023, 2003, 1037, 2742, 102], [101, 2054, 2003, 2023, 102, 0]]),
    "attention_mask": torch.tensor([[1, 1, 1, 1, 1, 1], [1, 1, 1, 1, 1, 0]])
}
outputs = model(**batch)

```

那么预测就是

```
tensor([[ 2.3, -1.2],    # 第一条代码的预测分数（[敏感代码得分, 普通代码得分]）
[-0.5,  1.5]])   # 第二条代码的预测分数
```

### 计算损失

这个也是我们模型的一个判断标准

```
labels = torch.tensor([0, 1])  # 第一条是敏感代码（0），第二条是普通代码（1）
loss = criterion(outputs.logits, labels)

```

然后使用 Softmax 计算

```
Softmax(logits):
第一条：[ exp(2.3) / (exp(2.3) + exp(-1.2)), exp(-1.2) / (exp(2.3) + exp(-1.2)) ]
       ≈ [0.91, 0.09]  # 91% 认为是敏感代码
第二条：[ exp(-0.5) / (exp(-0.5) + exp(1.5)), exp(1.5) / (exp(-0.5) + exp(1.5)) ]
       ≈ [0.12, 0.88]  # 88% 认为是普通代码

```

之后就是计算损失值了

```
损失 = - log(真实类别的预测概率)
= -log(0.91) + -log(0.88)
= 0.095 + 0.127
≈ 0.222

```

这个值如果越小，代表我们的模型准确率越高

### 反向传播

```
loss.backward()
```

这个我们只需要知道目的就是

计算损失 loss 对模型参数（权重、偏置）的梯度。  
让模型知道「哪些权重需要调整」。

### 更新参数

```
optimizer.step()

```

使用 loss.backward() 计算出的梯度，更新模型参数，让模型更接近正确预测。

## 评估模型

```
# 评估模型
def evaluate(model, test_loader, device):
    model.eval()
    total_correct = 0
    with torch.no_grad():
        for batch in tqdm(test_loader, desc="评估"):
            inputs, labels = batch
            inputs = {key: val.to(device) for key, val in inputs.items()}
            labels = labels.to(device)
            outputs = model(**inputs)
            total_correct += (outputs.logits.argmax(dim=1) == labels).sum().item()
    accuracy = total_correct / len(test_loader.dataset)
    print(f"📊 测试集准确率: {accuracy:.4f}")
```

和训练的区别在于

训练 = 计算损失 + 反向传播 + 参数更新  
评估 = 仅计算准确率，不更新参数

## 数据集

寻找数据集也是非常重要的，首先我们需要确定什么敏感

简单说几个

### **个人信息**

```
姓名: 张三
身份证号: 123456789012345678
手机号: 13812345678
邮箱: user@example.com

```

```
{
    "name": "John Doe",
    "credit_card": "4111-1111-1111-1111",
    "cvv": "123",
    "expiry": "12/25"
}
```

但是我们就要给出反例让 AI 学习

姓名: 小明  
年龄: 25  
职业: 程序员

比如这个没有泄露敏感的个人信息我们就需要标记为 0

### **政治/暴力/色情**

这个的话也是非常敏感的，我们也需要检测

这个就不好举例子了

### **机密数据**

我们常见的比如 API 的 key

```
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

```

```
google_api_key: "AIzaSyD4-uUjVJtEXAMPLEAPIKEY"

```

```
{
    "aws": {
        "access_key": "AKIAIOSFODNN7EXAMPLE",
        "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    }
}

```

当然我们并不能有前面的名称就判断是敏感

比如

```
AWS_ACCESS_KEY_ID = "your-access-key-here"
AWS_SECRET_ACCESS_KEY = "your-secret-key-here"

```

```
google_api_key: "PLACEHOLDER_API_KEY"

```

后面的内容根本就是相当于占位符的意思，我们就需要标记为 0

### **配置信息**

比如我们的数据库配置

```
DB_HOST = "db.example.com"
DB_USER = "admin"
DB_PASS = "SuperSecretPassword123!"

```

在 java 中

```
database:
username: "root"
password: "mypassword"

```

还有 ssh 的密钥

```
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA7vO...EXAMPLE...Wg==
-----END RSA PRIVATE KEY-----

```

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAA...EXAMPLE...AB
-----END OPENSSH PRIVATE KEY-----

```

一些凭据

```
{
    "type": "service_account",
    "project_id": "my-project",
    "private_key": "-----BEGIN PRIVATE KEY-----
MIIEv...",
    "client_email": "my-service-account@my-project.iam.gserviceaccount.com"
}

```

SMTP 服务的数据

```
SMTP_HOST = "smtp.example.com"
SMTP_PORT = 587
SMTP_USER = "user@example.com"
SMTP_PASSWORD = "SuperSecretPassword!"

```

经常看见造成漏洞默认 JWT 密钥

常见的是在我们的代码中

```
import jwt

SECRET_KEY = "my_super_secret_key_12345"  
payload = {"user_id": 1, "role": "admin"}
token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

```

```
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JwtExample {
    private static final String SECRET_KEY = "1234567890abcdef"; 

    public static void main(String[] args) {
        String token = Jwts.builder()
                .setSubject("user123")
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                .compact();
        System.out.println("JWT Token: " + token);
    }
}

```

还有一些硬编码的密码

当然也要区别为占位符

```
import os

DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")

```

标记为 0

## 寻找数据集

首先就是我们常见的数据集网站了，不过也可以生成，比如常见的我们让 AI，都可以生成

```
import pandas as pd

# 创建更丰富的数据集
data = [
    ('API_KEY = "AIzaSyD4EXAMPLE"', 1),
    ('DB_PASSWORD = "password123"', 1),
    ('SECRET_KEY = "super_secret_123"', 1),
    ('os.system("rm -rf /")', 1),
    ('jwt.encode(payload, "hardcoded_jwt_secret", algorithm="HS256")', 1),
    ('conn = psycopg2.connect(dbname="testdb", user="admin", password="supersecure")', 1),
    ('AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"', 1),
    ('access_token = "ghp_rT0EXAMPLETOKEN"', 1),
    ('echo \'root:root\' | chpasswd', 1),
    ('exec("ls -l")', 1),
    ('requests.get("http://example.com?password=1234")', 1),
    ('DROP TABLE users;', 1),
    ('curl -X DELETE http://example.com/delete_all_data', 1),
    ('DEBUG = True', 1),
    ('log.debug("Database connected with password=supersecure")', 1),
    ('password = input("Enter password: ")', 0),
    ('print("Hello, world!")', 0),
    ('def add(a, b): return a + b', 0),
    ('import os', 0),
    ('if user_input == "admin": print("Welcome")', 0),
]

# 转换为 DataFrame
df = pd.DataFrame(data, columns=["code_snippet", "label"])

# 保存为 CSV 文件
df.to_csv("sensitive_data.csv", index=False, encoding="utf-8")
print("✅ 敏感数据集已生成：sensitive_data.csv")

```

![](images/20250312114527-6fdd82f8-fef4-1.png)

当然 AI 生成的数据也是可以多一些，特征是比较明显的，这种属于强有效数据，但是训练的话需要大量的数据集

这里我们就可以直接去找数据集了

### **Kaggle**

Kaggle 公司是由联合创始人兼首席执行官 AnthonyGoldbloom2010 年在墨尔本创立的，主要是为开发商和数据科学家提供举办机器学习竞赛、托管数据库、编写和分享代码的平台。这一平台已经吸引了许多科学家和开发者的关注，他们也纷纷入驻这一平台。这些科学家和开发者资源正是谷歌看中他们的地方。

Kaggle 是一个数据科学社区，旨在通过数据挖掘竞赛、数据集和代码分享来推动机器学习的发展。它于 2010 年成立，被谷歌于 2017 年收购。在 Kaggle 上，数据科学家和机器学习工程师可以参与竞赛和项目，分享和发现数据集，建立和参与数据科学团队。Kaggle 上的竞赛涵盖各种主题，包括自然语言处理、计算机视觉、预测分析、图像处理等等。

这上面有许多的数据集

![](images/20250312114530-71cf0742-fef4-1.png)  
比如钓鱼的数据集

![](images/20250312114532-72fc3fcd-fef4-1.png)

### Github

当然有些也会放在这里，不过 github 主要是什么内容都有

比如找到了这个项目

<https://github.com/DhilipSanjay/Detection-of-Sensitive-Data-Exposure-in-Images>

![](images/20250312114534-7451e84f-fef4-1.png)  
![](images/20250312114536-75498882-fef4-1.png)

这种一般也会给出数据集

我们看一些例子

```
[{"is_sensitive": 1, "data": "username:aaliyah, password:123456, email:aaliyah@gmail.com, phone no:4905036436"}, {"is_sensitive": 1, "data": "username:aaren, password:12345, email:aaren@yahoo.com, phone no:8292544966"}, {"is_sensitive": 1, "data": "username:aarika, password:123456789, email:aarika@hotmail.com, phone no:9185734304"}, {"is_sensitive": 1, "data": "username:aaron, password:iloveyou, email:aaron@aol.com, phone no:5834106229"}, {"is_sensitive": 1, "data": "username:aartjan, password:princess, email:aartjan@hotmail.co.uk, phone no:5337239459"}, {"is_sensitive": 1, "data": "username:aarushi, password:1234567, email:aarushi@hotmail.fr, phone no:9292731329"}, {"is_sensitive": 1, "data": "username:abagael, password:12345678, email:abagael@msn.com, phone no:3079524341"}, {"is_sensitive": 1, "data": "username:abagail, password:abc123, email:abagail@yahoo.fr, phone no:9762192739"}, {"is_sensitive": 1, "data": "username:abahri, password:nicole, email:abahri@wanadoo.fr, phone no:9695000713"}, {"is_sensitive": 1, "data": "username:abbas, password:daniel, email:abbas@orange.fr, phone no:4312565613"}
```

```
[{"is_sensitive": 0, "data": "A bartender is working at a saloon, serving drinks to customers. After he fills a stereotypically Irish man's bucket with beer, Carrie Nation and her followers burst inside. They assault the Irish man, pulling his hat over his eyes and then dumping the beer over his head. The group then begin wrecking the bar, smashing the fixtures, mirrors, and breaking the cash register. The bartender then sprays seltzer water in Nation's face before a group of policemen appear and order everybody to leave.[1]"}, {"is_sensitive": 0, "data": "The moon, painted with a smiling face hangs over a park at night. A young couple walking past a fence learn on a railing and look up. The moon smiles. They embrace, and the moon's smile gets bigger. They then sit down on a bench by a tree. The moon's view is blocked, causing him to frown. In the last scene, the man fans the woman with his hat because the moon has left the sky and is perched over her shoulder to see everything better."}, {"is_sensitive": 0, "data": "The film, just over a minute long, is composed of two shots. In the first, a girl sits at the base of an altar or tomb, her face hidden from the camera. At the center of the altar, a viewing portal displays the portraits of three U.S. Presidents\u2014Abraham Lincoln, James A. Garfield, and William McKinley\u2014each victims of assassination.
In the second shot, which runs just over eight seconds long, an assassin kneels feet of Lady Justice."}, {"is_sensitive": 0, "data": "Lasting just 61 seconds and consisting of two shots, the first shot is set in a wood during winter. The actor representing then vice-president Theodore Roosevelt enthusiastically hurries down a hillside towards a tree in the foreground. He falls once, but rights himself and cocks his rifle. Two other men, bearing signs reading "His Photographer" and "His Press Agent" respectively, follow him into the shot; the photographer sets up his camera. "Teddy" aims his rifle upward at the tree and fells what appears to be a common house cat, which he then proceeds to stab. "Teddy" holds his prize aloft, and the press agent takes notes. The second shot is taken in a slightly different part of the wood, on a path. "Teddy" rides the path on his horse towards the camera and out to the left of the shot, followed closely by the press agent and photographer, still dutifully holding their signs."}, {"is_sensitive": 0, "data": "The earliest known adaptation of the classic fairytale, this films shows Jack trading his cow for the beans, his mother forcing him to drop them in the front yard, and beig forced upstairs. As he sleeps, Jack is visited by a fairy who shows him glimpses of what will await him when he ascends the bean stalk. In this version, Jack is the son of a deposed king. When Jack wakes up, he finds the beanstalk has grown and he climbs to the top where he enters the giant's home. The giant finds Jack, who narrowly escapes. The giant chases Jack down the bean stalk, but Jack is able to cut it down before the giant can get to safety. He falls and is killed as Jack celebrates. The fairy then reveals that Jack may return home as a prince."}, {"is_sensitive": 0, "data": "Alice follows a large white rabbit down a "Rabbit-hole". She finds a tiny door. When she finds a bottle labeled "Drink me", she does, and shrinks, but not enough to pass through the door. She then eats something labeled "Eat me" and grows larger. She finds a fan when enables her to shrink enough to get into the "Garden" and try to get a "Dog" to play with her. She enters the "White Rabbit's tiny House," but suddenly resumes her normal size. In order to get out, she has to use the "magic fan."
She enters a kitchen, in which there is a cook and a woman holding a baby. She persuades the woman to give her the child and takes the infant outside after the cook starts throwing things around. The baby then turns into a pig and squirms out of her grip. "The Duchess's Cheshire Cat" appears and disappears a couple of times to Alice and directs her to the Mad Hatter's "Mad Tea-Party." After a while, she leaves.
The Queen invites Alice to join the "ROYAL PROCESSION": a parade of marching playing cards and others headed by the White Rabbit. When Alice "unintentionally offends the Queen", the latter summons the "Executioner". Alice "boxes the ears", then flees when all the playing cards come for her. Then she wakes up and realizes it was all a dream."}
```

我们直接拿这种训练也是 ok 的

### Google Dataset Search

Dataset Search 是一个搜索引擎，旨在统一检索网络上的数据集。它利用 schema.org 元数据对数据集进行索引，目前包含了 4600 多个域名的 3100 多万个数据集，主要集中在地球科学、社会科学和生物学等领域。尽管存在数据集的可发现性和引用问题，但谷歌通过提供 DOI 和开放许可信息等方式提高了数据集的重用性。

我们也可以用来搜寻敏感的信息

![](images/20250312114538-764ec322-fef4-1.png)

### Hugging Face Datasets

这个是专门为大模型训练使用的数据集

![](images/20250312114540-7777f937-fef4-1.png)

![](images/20250312114542-789f8380-fef4-1.png)

ok 然后我是需要 csv 格式，只需要整合一下就好了

## 最终集成

```
import torch
import torch.nn as nn
import torch.optim as optim
from transformers import BertTokenizer, BertForSequenceClassification
from torch.utils.data import DataLoader, Dataset
from sklearn.model_selection import train_test_split
import os
import glob
import pandas as pd
from tqdm import tqdm
from cryptography.fernet import Fernet

# 选择设备
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# 生成密钥
key = Fernet.generate_key()
cipher_suite = Fernet(key)


# 数据加密、解密和脱敏处理
def encrypt_code(code):
    return cipher_suite.encrypt(code.encode()).decode()


def decrypt_code(encrypted_code):
    return cipher_suite.decrypt(encrypted_code.encode()).decode()


def desensitize_code(code):
    return code.replace("os.system", "os.system_placeholder")


# 读取和预处理数据
def load_data(data_path):
    csv_files = glob.glob(data_path)
    data_list = [pd.read_csv(file) for file in csv_files]
    data = pd.concat(data_list, ignore_index=True)
    if 'code' not in data.columns or 'label' not in data.columns:
        raise ValueError("数据集必须包含 'code' 和 'label' 列！")
    data['code'] = data['code'].astype(str)
    data['encrypted_code'] = data['code'].apply(encrypt_code)
    data['desensitized_code'] = data['code'].apply(desensitize_code)
    return data['desensitized_code'], data['label']


# 自定义数据集类
class CodeDataset(Dataset):
    def __init__(self, texts, labels, tokenizer, max_len=128):
        self.texts = texts.tolist()
        self.labels = labels.tolist()
        self.tokenizer = tokenizer
        self.max_len = max_len

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        encoding = self.tokenizer(
            self.texts[idx],
            padding="max_length",
            truncation=True,
            max_length=self.max_len,
            return_tensors="pt"
        )
        return {key: val.squeeze(0) for key, val in encoding.items()}, torch.tensor(self.labels[idx])


# 训练模型
def train(model, train_loader, optimizer, criterion, device, epochs=3, model_path="models/model.pth"):
    model.train()
    for epoch in range(epochs):
        total_loss, total_correct = 0, 0
        for batch in tqdm(train_loader, desc=f"训练 Epoch {epoch + 1}"):
            inputs, labels = batch
            inputs = {key: val.to(device) for key, val in inputs.items()}
            labels = labels.to(device)

            optimizer.zero_grad()
            outputs = model(**inputs)
            loss = criterion(outputs.logits, labels)
            loss.backward()
            optimizer.step()

            total_loss += loss.item()
            total_correct += (outputs.logits.argmax(dim=1) == labels).sum().item()

        accuracy = total_correct / len(train_loader.dataset)
        print(f"✅ Epoch {epoch + 1}: Loss = {total_loss:.4f}, Accuracy = {accuracy:.4f}")

    torch.save(model.state_dict(), model_path)

    print(f"✅ 模型已保存到 {model_path}")


# 评估模型
def evaluate(model, test_loader, device):
    model.eval()
    total_correct = 0
    with torch.no_grad():
        for batch in tqdm(test_loader, desc="评估"):
            inputs, labels = batch
            inputs = {key: val.to(device) for key, val in inputs.items()}
            labels = labels.to(device)
            outputs = model(**inputs)
            total_correct += (outputs.logits.argmax(dim=1) == labels).sum().item()
    accuracy = total_correct / len(test_loader.dataset)
    print(f"📊 测试集准确率: {accuracy:.4f}")


# 主程序
if __name__ == "__main__":
    data_path = "1.csv"
    model_path = "AI/model/model.pth"
    X, y = load_data(data_path)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.1, random_state=42)
    tokenizer = BertTokenizer.from_pretrained("bert-base-uncased")

    train_dataset = CodeDataset(X_train, y_train, tokenizer)
    test_dataset = CodeDataset(X_test, y_test, tokenizer)

    train_loader = DataLoader(train_dataset, batch_size=16, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=16)

    model = BertForSequenceClassification.from_pretrained("bert-base-uncased", num_labels=len(set(y_train)))
    if os.path.exists(model_path):
        print("🔄 加载已有模型，继续训练...")
        model.load_state_dict(torch.load(model_path, map_location=device))
    model.to(device)
    optimizer = optim.AdamW(model.parameters(), lr=2e-5)
    criterion = nn.CrossEntropyLoss()

    train(model, train_loader, optimizer, criterion, device, epochs=3, model_path=model_path)
    evaluate(model, test_loader, device)

```

我们开始训练

emmmm，数据越大训练就越久，而且你的 CPU 会一直拉满，所以还是建议租借去训练

![](images/20250312114543-796b8944-fef4-1.png)

一轮就需要 10 个小时，而且得训练很多轮去了

一般我们还需要更换数据集或者训练多次准确率会有提高
