/*
 * Copyright 2018 Xiaomi, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package advisor

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/XiaoMi/soar/ast"
	"github.com/XiaoMi/soar/common"

	"github.com/kr/pretty"
	"github.com/percona/go-mysql/query"
	tidb "github.com/pingcap/parser/ast"
	"vitess.io/vitess/go/vt/sqlparser"
)

// Query4Audit 待评审的SQL结构体，由原SQL和其对应的抽象语法树组成
type Query4Audit struct {
	Query  string              // 查询语句
	Stmt   sqlparser.Statement // 通过Vitess解析出的抽象语法树
	TiStmt []tidb.StmtNode     // 通过TiDB解析出的抽象语法树
}

// NewQuery4Audit return a struct for Query4Audit
func NewQuery4Audit(sql string, options ...string) (*Query4Audit, error) {
	var err, vErr error
	var charset string
	var collation string

	if len(options) > 0 {
		charset = options[0]
	}

	if len(options) > 1 {
		collation = options[1]
	}

	q := &Query4Audit{Query: sql}
	// vitess 语法解析不上报，以 tidb parser 为主
	q.Stmt, vErr = sqlparser.Parse(sql)
	if vErr != nil {
		common.Log.Warn("NewQuery4Audit vitess parse Error: %s, Query: %s", vErr.Error(), sql)
	}

	// TODO: charset, collation
	// tidb parser 语法解析
	q.TiStmt, err = ast.TiParse(sql, charset, collation)
	return q, err
}

// Rule 评审规则元数据结构
type Rule struct {
	Item     string                  `json:"Item"`     // 规则代号
	Severity string                  `json:"Severity"` // 危险等级：L[0-8], 数字越大表示级别越高
	Summary  string                  `json:"Summary"`  // 规则摘要
	Content  string                  `json:"Content"`  // 规则解释
	Case     string                  `json:"Case"`     // SQL示例
	Position int                     `json:"Position"` // 建议所处SQL字符位置，默认0表示全局建议
	Func     func(*Query4Audit) Rule `json:"-"`        // 函数名
}

/*

## Item单词缩写含义

* ALI   Alias(AS)
* ALT   Alter
* ARG   Argument
* CLA   Classic
* COL   Column
* DIS   Distinct
* ERR   Error, 特指MySQL执行返回的报错信息, ERR.000为vitess语法错误，ERR.001为执行错误，ERR.002为EXPLAIN错误
* EXP   Explain, 由explain模块给
* FUN   Function
* IDX   Index, 由index模块给
* JOI   Join
* KEY   Key
* KWR   Keyword
* LCK	Lock
* LIT   Literal
* PRO   Profiling, 由profiling模块给
* RES   Result
* SEC   Security
* STA   Standard
* SUB   Subquery
* TBL   TableName
* TRA   Trace, 由trace模块给

*/

// HeuristicRules 启发式规则列表
var HeuristicRules map[string]Rule

func init() {
	InitHeuristicRules()
}

// InitHeuristicRules ...
func InitHeuristicRules() {
	HeuristicRules = map[string]Rule{
		"OK": {
			Item:     "OK",
			Severity: "L0",
			Summary:  "OK",
			Content:  `OK`,
			Case:     "OK",
			Func:     (*Query4Audit).RuleOK,
		},
		"ALI.001": {
			Item:     "ALI.001",
			Severity: "L0",
			Summary:  "It is recommended to use the AS keyword to explicitly declare an alias",
			Content:  `In column or table aliases (such as "tbl AS alias"), explicit use of the AS keyword is easier to understand than implicit aliases (such as "tbl alias"). `,
			Case:     "select name from tbl t1 where id <1000",
			Func:     (*Query4Audit).RuleImplicitAlias,
		},
		"ALI.002": {
			Item:     "ALI.002",
			Severity: "L8",
			Summary:  "It is not recommended to set an alias for the column wildcard character'*'",
			Content:  `Example: "SELECT tbl.* col1, col2" The above SQL sets aliases for the column wildcards. Such SQL may have logic errors. You might be looking for col1, but instead of it, the last column of tbl is renamed. `,
			Case:     "select tbl.* as c1,c2,c3 from tbl where id <1000",
			Func:     (*Query4Audit).RuleStarAlias,
		},
		"ALI.003": {
			Item:     "ALI.003",
			Severity: "L1",
			Summary:  "The alias should not be the same as the name of the table or column",
			Content:  `The alias of the table or column is the same as its real name. Such an alias will make the query more difficult to distinguish. `,
			Case:     "select name from tbl as tbl where id <1000",
			Func:     (*Query4Audit).RuleSameAlias,
		},
		"ALT.001": {
			Item:     "ALT.001",
			Severity: "L4",
			Summary:  "Modifying the default character set of the table will not change the character set of each field of the table",
			Content:  `Many beginners will mistake ALTER TABLE tbl_name [DEFAULT] CHARACTER SET'UTF8' to modify the character set of all fields, but in fact it will only affect the subsequent newly added fields and will not change the characters of the existing fields in the table set. If you want to modify the character set of all fields in the entire table, it is recommended to use ALTER TABLE tbl_name CONVERT TO CHARACTER SET charset_name;`,
			Case:     "ALTER TABLE tbl_name CONVERT TO CHARACTER SET charset_name;",
			Func:     (*Query4Audit).RuleAlterCharset,
		},
		"ALT.002": {
			Item:     "ALT.002",
			Severity: "L2",
			Summary:  "Multiple ALTER request suggestions for the same table are combined into one",
			Content:  `Each table structure change will have an impact on online services, even if it is possible to adjust through online tools, please try to reduce the number of operations by merging ALTER requests. `,
			Case:     "ALTER TABLE tbl ADD COLUMN col int, ADD INDEX idx_col (`col`);",
			Func:     (*Query4Audit).RuleOK, // This suggestion is given in indexAdvisor
		},
		"ALT.003": {
			Item:     "ALT.003",
			Severity: "L0",
			Summary:  "Delete is listed as a high-risk operation. Please check whether the business logic is still dependent before the operation.",
			Content:  `If the business logic dependency is not completely eliminated, after the column is deleted, the data may not be written or the deleted column data cannot be queried, which may cause the program to be abnormal. In this case, even if the backup data is rolled back, the data requested by the user will be lost. `,
			Case:     "ALTER TABLE tbl DROP COLUMN col;",
			Func:     (*Query4Audit).RuleAlterDropColumn,
		},
		"ALT.004": {
			Item:     "ALT.004",
			Severity: "L0",
			Summary:  "Deleting primary keys and foreign keys is a high-risk operation, please confirm the impact with DBA before operation",
			Content:  `Primary key and foreign key are two important constraints in relational databases. Deleting existing constraints will break the existing business logic. Before operating, please confirm the impact with the DBA and think twice. `,
			Case:     "ALTER TABLE tbl DROP PRIMARY KEY;",
			Func:     (*Query4Audit).RuleAlterDropKey,
		},
		"ARG.001": {
			Item:     "ARG.001",
			Severity: "L4",
			Summary:  "It is not recommended to use the preceding wildcard search",
			Content:  `For example, "%foo", if the query parameter has a wildcard in the preceding term, the existing index cannot be used. `,
			Case:     "select c1,c2,c3 from tbl where name like'%foo'",
			Func:     (*Query4Audit).RulePrefixLike,
		},
		"ARG.002": {
			Item:     "ARG.002",
			Severity: "L1",
			Summary:  "LIKE query without wildcards",
			Content:  `LIKE query that does not contain wildcards may have a logic error, because it is logically the same as an equivalent query. `,
			Case:     "select c1,c2,c3 from tbl where name like'foo'",
			Func:     (*Query4Audit).RuleEqualLike,
		},
		"ARG.003": {
			Item:     "ARG.003",
			Severity: "L4",
			Summary:  "The parameter comparison contains implicit conversion, and the index cannot be used",
			Content:  "Implicit type conversion has the risk of not hitting the index. In the case of high concurrency and large data volume, the consequences of not hitting the index are very serious.",
			Case:     "SELECT * FROM sakila.film WHERE length >= '60';",
			Func:     (*Query4Audit).RuleOK, // The suggestion is given in IndexAdvisor, RuleImplicitConversion
		},
		"ARG.004": {
			Item:     "ARG.004",
			Severity: "L4",
			Summary:  "IN (NULL)/NOT IN (NULL) is never true",
			Content:  "The correct way is col IN ('val1','val2','val3') OR col IS NULL",
			Case:     "SELECT * FROM tb WHERE col IN (NULL);",
			Func:     (*Query4Audit).RuleIn,
		},
		"ARG.005": {
			Item:     "ARG.005",
			Severity: "L1",
			Summary:  "IN should be used with caution, too many elements will cause a full table scan",
			Content:  `Such as: select id from t where num in(1,2,3) For continuous values, don't use IN if you can use BETWEEN: select id from t where num between 1 and 3. And when the IN value is too much, MySQL may also enter a full table scan, causing a sharp drop in performance. `,
			Case:     "select id from t where num in(1,2,3)",
			Func:     (*Query4Audit).RuleIn,
		},
		"ARG.006": {
			Item:     "ARG.006",
			Severity: "L1",
			Summary:  "Try to avoid the NULL value judgment of the field in the WHERE clause",
			Content:  `Using IS NULL or IS NOT NULL may cause the engine to give up using the index and perform a full table scan, such as: select id from t where num is null; you can set a default value of 0 on num to ensure that the num column in the table is not NULL Value, and then query like this: select id from t where num=0;`,
			Case:     "select id from t where num is null",
			Func:     (*Query4Audit).RuleIsNullIsNotNull,
		},
		"ARG.007": {
			Item:     "ARG.007",
			Severity: "L3",
			Summary:  "Avoid using pattern matching",
			Content:  `Performance is the biggest disadvantage of using pattern matching operators. Another problem with using LIKE or regular expressions for pattern matching is that it may return unexpected results. The best solution is to use a special search engine technology to replace SQL, such as Apache Lucene. Another alternative is to save the results to reduce repeated search overhead. If you must use SQL, please consider using third-party extensions like FULLTEXT indexes in MySQL. But more broadly, you don't necessarily have to use SQL to solve all problems. `,
			Case:     "select c_id,c2,c3 from tbl where c2 like'test%'",
			Func:     (*Query4Audit).RulePatternMatchingUsage,
		},
		"ARG.008": {
			Item:     "ARG.008",
			Severity: "L1",
			Summary:  "Please try to use IN predicate when OR query index column",
			Content:  `IN-list predicate can be used for index search, and the optimizer can sort the IN-list to match the sorting sequence of the index, so as to obtain a more effective search. Please note that the IN-list must only contain constants, or keep constant values ​​during the execution of the query block, such as external references. `,
			Case:     "SELECT c1,c2,c3 FROM tbl WHERE c1 = 14 OR c1 = 17",
			Func:     (*Query4Audit).RuleORUsage,
		},
		"ARG.009": {
			Item:     "ARG.009",
			Severity: "L1",
			Summary:  "The string in quotation marks contains spaces at the beginning or end",
			Content:  `If there are spaces before and after the VARCHAR column, it may cause logic problems. For example, in MySQL 5.5,'a' and'a' may be considered the same value in the query. `,
			Case:     "SELECT'abc'",
			Func:     (*Query4Audit).RuleSpaceWithQuote,
		},
		"ARG.010": {
			Item:     "ARG.010",
			Severity: "L1",
			Summary:  "Do not use hints, such as: sql_no_cache, force index, ignore key, straight join, etc.",
			Content:  `hint is used to force SQL to execute according to a certain execution plan, but as the amount of data changes, we cannot guarantee that our original prediction is correct. `,
			Case:     "SELECT * FROM t1 USE INDEX (i1) ORDER BY a;",
			Func:     (*Query4Audit).RuleHint,
		},
		"ARG.011": {
			Item:     "ARG.011",
			Severity: "L3",
			Summary:  "Don't use negative query, such as: NOT IN/NOT LIKE",
			Content:  `Please try not to use negative queries, which will cause a full table scan and have a greater impact on query performance. `,
			Case:     "select id from t where num not in(1,2,3);",
			Func:     (*Query4Audit).RuleNot,
		},
		"ARG.012": {
			Item:     "ARG.012",
			Severity: "L2",
			Summary:  "Too much data for one-time INSERT/REPLACE",
			Content:  "A single INSERT/REPLACE statement has poor performance for inserting large amounts of data in batches, and may even cause synchronization delays from the database. In order to improve performance and reduce the impact of batch write data on the synchronization delay of the slave database, it is recommended to insert in batches. .",
			Case:     "INSERT INTO tb (a) VALUES (1), (2)",
			Func:     (*Query4Audit).RuleInsertValues,
		},
		"ARG.013": {
			Item:     "ARG.013",
			Severity: "L0",
			Summary:  "Chinese full-width quotation marks are used in DDL statements",
			Content:  "Chinese full-width quotation marks \"\" or ‘’ are used in the DDL statement. This may be a writing error. Please confirm whether it meets expectations.",
			Case:     "CREATE TABLE tb (a varchar(10) default'“”'",
			Func:     (*Query4Audit).RuleFullWidthQuote,
		},
		"ARG.014": {
			Item:     "ARG.014",
			Severity: "L4",
			Summary:  "There are column names in the IN condition, which may lead to the expansion of the data matching range",
			Content:  `Such as: delete from t where id in(1, 2, id) may cause the entire table data to be deleted by mistake. Please carefully check the correctness of the IN conditions. `,
			Case:     "select id from t where id in(1, 2, id)",
			Func:     (*Query4Audit).RuleIn,
		},
		"CLA.001": {
			Item:     "CLA.001",
			Severity: "L4",
			Summary:  "The outermost SELECT does not specify the WHERE condition",
			Content:  `The SELECT statement has no WHERE clause, and may check more rows than expected (full table scan). If precision is not required for SELECT COUNT(*) type requests, it is recommended to use SHOW TABLE STATUS or EXPLAIN instead. `,
			Case:     "select id from tbl",
			Func:     (*Query4Audit).RuleNoWhere,
		},
		"CLA.002": {
			Item:     "CLA.002",
			Severity: "L3",
			Summary:  "ORDER BY RAND() is not recommended",
			Content:  `ORDER BY RAND() is a very inefficient method of retrieving random rows from the result set, because it sorts the entire result and discards most of its data. `,
			Case:     "select name from tbl where id <1000 order by rand(number)",
			Func:     (*Query4Audit).RuleOrderByRand,
		},
		"CLA.003": {
			Item:     "CLA.003",
			Severity: "L2",
			Summary:  "It is not recommended to use LIMIT query with OFFSET",
			Content:  `The complexity of using LIMIT and OFFSET to page the result set is O(n^2), and it will cause performance problems as the data increases. Using "bookmark" scanning method to achieve higher efficiency of paging. `,
			Case:     "select c1,c2 from tbl where name=xx order by number limit 1 offset 20",
			Func:     (*Query4Audit).RuleOffsetLimit,
		},
		"CLA.004": {
			Item:     "CLA.004",
			Severity: "L2",
			Summary:  "It is not recommended to group by constants",
			Content:  `GROUP BY 1 means group by the first column. If you use numbers in the GROUP BY clause instead of expressions or column names, it may cause problems when the order of the query columns is changed. `,
			Case:     "select col1,col2 from tbl group by 1",
			Func:     (*Query4Audit).RuleGroupByConst,
		},
		"CLA.005": {
			Item:     "CLA.005",
			Severity: "L2",
			Summary:  "ORDER BY constant column has no meaning",
			Content:  `There may be an error in SQL logic; at most it is just a useless operation and will not change the query result. `,
			Case:     "select id from test where id=1 order by id",
			Func:     (*Query4Audit).RuleOrderByConst,
		},
		"CLA.006": {
			Item:     "CLA.006",
			Severity: "L4",
			Summary:  "Group BY or ORDER BY in different tables",
			Content:  `This will force the use of temporary tables and filesort, which may cause huge performance hazards, and may consume a lot of memory and temporary space on the disk. `,
			Case:     "select tb1.col, tb2.col from tb1, tb2 where id=1 group by tb1.col, tb2.col",
			Func:     (*Query4Audit).RuleDiffGroupByOrderBy,
		},
		"CLA.007": {
			Item:     "CLA.007",
			Severity: "L2",
			Summary:  "ORDER BY statement cannot use indexes for multiple different conditions and sorts in different directions",
			Content:  `All expressions in the ORDER BY clause must be sorted in a uniform ASC or DESC direction in order to take advantage of the index. `,
			Case:     "select c1,c2,c3 from t1 where c1='foo' order by c2 desc, c3 asc",
			Func:     (*Query4Audit).RuleMixOrderBy,
		},
		"CLA.008": {
			Item:     "CLA.008",
			Severity: "L2",
			Summary:  "Please add ORDER BY condition for GROUP BY display",
			Content:  `By default, MySQL will sort'GROUP BY col1, col2, ...' requests in the following order:'ORDER BY col1, col2, ...'. If the GROUP BY statement does not specify the ORDER BY condition, it will cause unnecessary sorting. If sorting is not required, it is recommended to add'ORDER BY NULL'. `,
			Case:     "select c1,c2,c3 from t1 where c1='foo' group by c2",
			Func:     (*Query4Audit).RuleExplicitOrderBy,
		},
		"CLA.009": {
			Item:     "CLA.009",
			Severity: "L2",
			Summary:  "The condition of ORDER BY is an expression",
			Content:  `When the ORDER BY condition is an expression or a function, a temporary table will be used. If the WHERE or WHERE condition is not specified, the performance will be poor if the result set returned is large. `,
			Case:     "select description from film where title ='ACADEMY DINOSAUR' order by length-language_id;",
			Func:     (*Query4Audit).RuleOrderByExpr,
		},
		"CLA.010": {
			Item:     "CLA.010",
			Severity: "L2",
			Summary:  "The condition of GROUP BY is an expression",
			Content:  `When the GROUP BY condition is an expression or a function, a temporary table will be used. If the WHERE or WHERE condition is not specified and the result set returned is large, the performance will be poor. `,
			Case:     "select description from film where title ='ACADEMY DINOSAUR' GROUP BY length-language_id;",
			Func:     (*Query4Audit).RuleGroupByExpr,
		},
		"CLA.011": {
			Item:     "CLA.011",
			Severity: "L1",
			Summary:  "It is recommended to add a comment to the table",
			Content:  `Adding comments to the table can make the meaning of the table more clear, which will bring great convenience to future maintenance. `,
			Case:     "CREATE TABLE `test1` (`ID` bigint(20) NOT NULL AUTO_INCREMENT,`c1` varchar(128) DEFAULT NULL,PRIMARY KEY (`ID`)) ENGINE=InnoDB DEFAULT CHARSET=utf8",
			Func:     (*Query4Audit).RuleTblCommentCheck,
		},
		"CLA.012": {
			Item:     "CLA.012",
			Severity: "L2",
			Summary:  "Decompose complex bound-footed queries into several simple queries",
			Content:  `SQL is a very expressive language, you can accomplish many things in a single SQL query or a single statement. But this does not mean that you must use only one line of code, or that it is a good idea to use one line of code to get every task. A common consequence of obtaining all results with one query is to get a Cartesian product. This happens when there are no conditions between the two tables in the query to restrict their relationship. There is no corresponding restriction and directly use two tables for join query, you will get a combination of each row in the first table and each row in the second table. Each such combination will become a row in the result set, and eventually you will get a result set with a large number of rows. It is important to consider that these queries are difficult to write, difficult to modify, and difficult to debug. The increasing number of database query requests should be expected. Managers want more complex reports and add more fields to the user interface. If your design is complex and a single query, it will be time-consuming and laborious to expand them. For you or the project, time spent on these things is not worth it. Break the complex spaghetti query into a few simple queries. When you split a complex SQL query, the result may be many similar queries, which may differ only in data types. Writing all these queries is very tedious, so it is best to have a program that automatically generates these codes. SQL code generation is a good application. Although SQL supports solving complex problems with one line of code, don't do unrealistic things. `,
			Case:     "This is a very long and very long SQL, the case is omitted.",
			Func:     (*Query4Audit).RuleSpaghettiQueryAlert,
		},
		/*
			https://www.datacamp.com/community/tutorials/sql-tutorial-query
			The HAVING Clause
			The HAVING clause was originally added to SQL because the WHERE keyword could not be used with aggregate functions. HAVING is typically used with the GROUP BY clause to restrict the groups of returned rows to only those that meet certain conditions. However, if you use this clause in your query, the index is not used, which -as you already know- can result in a query that doesn't really perform all that well.

			If you’re looking for an alternative, consider using the WHERE clause. Consider the following queries:

			SELECT state, COUNT(*)
			  FROM Drivers
			 WHERE state IN ('GA', 'TX')
			 GROUP BY state
			 ORDER BY state
			SELECT state, COUNT(*)
			  FROM Drivers
			 GROUP BY state
			HAVING state IN ('GA', 'TX')
			 ORDER BY state
			The first query uses the WHERE clause to restrict the number of rows that need to be summed, whereas the second query sums up all the rows in the table and then uses HAVING to throw away the sums it calculated. In these types of cases, the alternative with the WHERE clause is obviously the better one, as you don’t waste any resources.

			You see that this is not about limiting the result set, rather about limiting the intermediate number of records within a query.

			Note that the difference between these two clauses lies in the fact that the WHERE clause introduces a condition on individual rows, while the HAVING clause introduces a condition on aggregations or results of a selection where a single result, such as MIN, MAX, SUM,… has been produced from multiple rows.
		*/
		"CLA.013": {
			Item:     "CLA.013",
			Severity: "L3",
			Summary:  "The HAVING clause is not recommended",
			Content:  `Rewrite the HAVING clause of the query as the query condition in the WHERE, and the index can be used during query processing. `,
			Case:     "SELECT s.c_id,count(s.c_id) FROM s where c = test GROUP BY s.c_id HAVING s.c_id <> '1660' AND s.c_id <> '2' order by s.c_id",
			Func:     (*Query4Audit).RuleHavingClause,
		},
		"CLA.014": {
			Item:     "CLA.014",
			Severity: "L2",
			Summary:  "It is recommended to use TRUNCATE instead of DELETE when deleting the entire table",
			Content:  `It is recommended to use TRUNCATE instead of DELETE when deleting the entire table`,
			Case:     "delete from tbl",
			Func:     (*Query4Audit).RuleNoWhere,
		},
		"CLA.015": {
			Item:     "CLA.015",
			Severity: "L4",
			Summary:  "UPDATE does not specify the WHERE condition",
			Content:  `UPDATE does not specify the WHERE condition is generally fatal, please think twice`,
			Case:     "update tbl set col=1",
			Func:     (*Query4Audit).RuleNoWhere,
		},
		"CLA.016": {
			Item:     "CLA.016",
			Severity: "L2",
			Summary:  "Don't UPDATE the primary key",
			Content:  `The primary key is the unique identifier of the record in the data table. It is not recommended to update the primary key column frequently. This will affect the metadata statistics and affect the normal query. `,
			Case:     "update tbl set col=1",
			Func:     (*Query4Audit).RuleOK, // It is recommended to give RuleUpdatePrimaryKey in indexAdvisor
		},
		"COL.001": {
			Item:     "COL.001",
			Severity: "L1",
			Summary:  "It is not recommended to use SELECT * type query",
			Content:  `When the table structure changes, using the * wildcard to select all columns will cause the meaning and behavior of the query to change, which may cause the query to return more data. `,
			Case:     "select * from tbl where id=1",
			Func:     (*Query4Audit).RuleSelectStar,
		},
		"COL.002": {
			Item:     "COL.002",
			Severity: "L2",
			Summary:  "INSERT/REPLACE does not specify the column name",
			Content:  `When the table structure changes, if the INSERT or REPLACE request does not explicitly specify the column name, the result of the request will be different from what you expected; it is recommended to use "INSERT INTO tbl(col1, col2)VALUES ..." instead. `,
			Case:     "insert into tbl values(1,'name')",
			Func:     (*Query4Audit).RuleInsertColDef,
		},
		"COL.003": {
			Item:     "COL.003",
			Severity: "L2",
			Summary:  "It is recommended to modify the auto-increment ID to an unsigned type",
			Content:  `It is recommended to modify the auto-increment ID to an unsigned type`,
			Case:     "create table test(`id` int(11) NOT NULL AUTO_INCREMENT)",
			Func:     (*Query4Audit).RuleAutoIncUnsigned,
		},
		"COL.004": {
			Item:     "COL.004",
			Severity: "L1",
			Summary:  "Please add a default value for the column",
			Content:  `Please add a default value for the column, if it is an ALTER operation, please don't forget to write the default value of the original field. The field has no default value, and the table structure cannot be changed online when the table is large. `,
			Case:     "CREATE TABLE tbl (col int) ENGINE=InnoDB;",
			Func:     (*Query4Audit).RuleAddDefaultValue,
		},
		"COL.005": {
			Item:     "COL.005",
			Severity: "L1",
			Summary:  "The column is not commented",
			Content:  `It is recommended to add a comment to each column in the table to clarify the meaning and function of each column in the table. `,
			Case:     "CREATE TABLE tbl (col int) ENGINE=InnoDB;",
			Func:     (*Query4Audit).RuleColCommentCheck,
		},
		"COL.006": {
			Item:     "COL.006",
			Severity: "L3",
			Summary:  "The table contains too many columns",
			Content:  `The table contains too many columns`,
			Case:     "CREATE TABLE tbl (cols ....);",
			Func:     (*Query4Audit).RuleTooManyFields,
		},
		"COL.007": {
			Item:     "COL.007",
			Severity: "L3",
			Summary:  "The table contains too many text/blob columns",
			Content:  fmt.Sprintf(`The table contains more than %d text/blob columns`, common.Config.MaxTextColsCount),
			Case:     "CREATE TABLE tbl (cols ....);",
			Func:     (*Query4Audit).RuleTooManyFields,
		},
		"COL.008": {
			Item:     "COL.008",
			Severity: "L1",
			Summary:  "You can use VARCHAR instead of CHAR, VARBINARY instead of BINARY",
			Content:  `The storage space is small for the first variable length field, which can save storage space. Secondly, for queries, the search efficiency in a relatively small field is obviously higher. `,
			Case:     "create table t1(id int,name char(20),last_time date)",
			Func:     (*Query4Audit).RuleVarcharVSChar,
		},
		"COL.009": {
			Item:     "COL.009",
			Severity: "L2",
			Summary:  "It is recommended to use precise data types",
			Content:  `Actually, any design that uses FLOAT, REAL or DOUBLE PRECISION data types may be an anti-pattern. The value range of floating point numbers used by most applications does not need to reach the maximum/minimum range defined by the IEEE 754 standard. When calculating the total, the accumulated impact of inexact floating-point numbers is serious. Use the NUMERIC or DECIMAL type in SQL to replace FLOAT and similar data types for fixed-precision decimal storage. These data types store data exactly according to the precision you specified when you defined this column. Do not use floating-point numbers as much as possible. `,
			Case:     "CREATE TABLE tab2 (p_id BIGINT UNSIGNED NOT NULL,a_id BIGINT UNSIGNED NOT NULL,hours float not null,PRIMARY KEY (p_id, a_id))",
			Func:     (*Query4Audit).RuleImpreciseDataType,
		},
		"COL.010": {
			Item:     "COL.010",
			Severity: "L2",
			Summary:  "It is not recommended to use ENUM/BIT/SET data type",
			Content:  `ENUM defines the type of value in the column. When using a string to represent the value in ENUM, the data actually stored in the column is the ordinal number of these values ​​at the time of definition. Therefore, the data in this column is byte-aligned. When you perform a sorting query, the results are sorted according to the actual stored ordinal value, not the alphabetical order of the string value. This may not be what you want. There is no syntax for adding or deleting a value from an ENUM or check constraint; you can only redefine this column with a new set. If you plan to discard an option, you may be annoyed by historical data. As a strategy, changing metadata—that is, changing the definition of tables and columns—should be uncommon, and pay attention to testing and quality assurance. There is a better solution to constrain the optional values ​​in a column: create a check table, each row contains a candidate value that is allowed in the column; then declare a foreign key constraint on the old table that references the new table. `,
			Case:     "create table tab1(status ENUM('new','in progress','fixed'))",
			Func:     (*Query4Audit).RuleValuesInDefinition,
		},
		// 这个建议从sqlcheck迁移来的，实际生产环境每条建表SQL都会给这条建议，看多了会不开心。
		"COL.011": {
			Item:     "COL.011",
			Severity: "L0",
			Summary:  "NULL is used when a unique constraint is required, and NOT NULL is used only when the column cannot have missing values",
			Content:  `NULL and 0 are different, 10 multiplied by NULL or NULL. NULL is not the same as an empty string. The result of combining a string with NULL in standard SQL is still NULL. NULL and FALSE are also different. If NULL is involved in the three Boolean operations of AND, OR, and NOT, many people are confused by the result. When you declare a column as NOT NULL, it means that every value in the column must exist and be meaningful. Use NULL to represent a null value that does not exist in any type. When you declare a column as NOT NULL, it means that every value in the column must exist and be meaningful. `,
			Case:     "select c1,c2,c3 from tbl where c4 is null or c4 <> 1",
			Func:     (*Query4Audit).RuleNullUsage,
		},
		"COL.012": {
			Item:     "COL.012",
			Severity: "L5",
			Summary:  "TEXT, BLOB and JSON type fields are not recommended to be set to NOT NULL",
			Content:  `TEXT, BLOB, and JSON type fields cannot specify non-NULL default values. If the NOT NULL restriction is added, writing data without specifying a value for the field may cause writing failure. `,
			Case:     "CREATE TABLE `tb`(`c` longblob NOT NULL);",
			Func:     (*Query4Audit).RuleBLOBNotNull,
		},
		"COL.013": {
			Item:     "COL.013",
			Severity: "L4",
			Summary:  "TIMESTAMP type default value check exception",
			Content:  `TIMESTAMP type recommends setting the default value, and it is not recommended to use 0 or 0000-00-00 00:00:00 as the default value. Consider using 1970-08-02 01:01:01`,
			Case:     "CREATE TABLE tbl( `id` bigint not null, `create_time` timestamp);",
			Func:     (*Query4Audit).RuleTimestampDefault,
		},
		"COL.014": {
			Item:     "COL.014",
			Severity: "L5",
			Summary:  "A character set is specified for the column",
			Content:  `It is recommended that the column and the table use the same character set, do not specify the character set of the column separately. `,
			Case:     "CREATE TABLE `tb2` (`id` int(11) DEFAULT NULL, `col` char(10) CHARACTER SET utf8 DEFAULT NULL)",
			Func:     (*Query4Audit).RuleColumnWithCharset,
		},
		// https://stackoverflow.com/questions/3466872/why-cant-a-text-column-have-a-default-value-in-mysql
		"COL.015": {
			Item:     "COL.015",
			Severity: "L4",
			Summary:  "TEXT, BLOB and JSON type fields cannot be specified with non-NULL default values",
			Content:  `TEXT, BLOB and JSON type fields in the MySQL database cannot be specified with non-NULL default values. The maximum length of TEXT is 2^16-1 characters, the maximum length of MEDIUMTEXT is 2^32-1 characters, and the maximum length of LONGTEXT is 2^64-1 characters. `,
			Case:     "CREATE TABLE `tbl` (`c` blob DEFAULT NULL);",
			Func:     (*Query4Audit).RuleBlobDefaultValue,
		},
		"COL.016": {
			Item:     "COL.016",
			Severity: "L1",
			Summary:  "Integer definition is recommended to use INT(10) or BIGINT(20)",
			Content:  `INT(M) In the integer data type, M represents the maximum display width. In INT(M), the value of M has nothing to do with how much storage space INT(M) occupies. INT(3), INT(4), INT(8) all occupy 4 bytes of storage space on the disk. In higher versions of MySQL, it is no longer recommended to set the integer display width. `,
			Case:     "CREATE TABLE tab (a INT(1));",
			Func:     (*Query4Audit).RuleIntPrecision,
		},
		"COL.017": {
			Item:     "COL.017",
			Severity: "L2",
			Summary:  "VARCHAR definition length is too long",
			Content:  fmt.Sprintf(`varchar is a variable-length string, storage space is not allocated in advance, and the length should not exceed %d. If the storage length is too long, MySQL will define the field type as text, and create a separate table with the primary key to correspond , To avoid affecting the index efficiency of other fields.`, common.Config.MaxVarcharLength),
			Case:     "CREATE TABLE tab (a varchar(3500));",
			Func:     (*Query4Audit).RuleVarcharLength,
		},
		"COL.018": {
			Item:     "COL.018",
			Severity: "L9",
			Summary:  "A field type that is not recommended is used in the table building statement",
			Content:  "The following field types are not recommended:" + strings.Join(common.Config.ColumnNotAllowType, ", "),
			Case:     "CREATE TABLE tab (a BOOLEAN);",
			Func:     (*Query4Audit).RuleColumnNotAllowType,
		},
		"COL.019": {
			Item:     "COL.019",
			Severity: "L1",
			Summary:  "It is not recommended to use time data types with accuracy below the second level",
			Content:  "The storage space consumption brought by the use of high-precision time data types is relatively large; MySQL can only support time data types accurate to microseconds above 5.6.4, and version compatibility issues need to be considered when using it.",
			Case:     "CREATE TABLE t1 (t TIME(3), dt DATETIME(6));",
			Func:     (*Query4Audit).RuleTimePrecision,
		},
		"DIS.001": {
			Item:     "DIS.001",
			Severity: "L1",
			Summary:  "Eliminate unnecessary DISTINCT conditions",
			Content:  `Too many DISTINCT conditions are a symptom of complex footwear queries. Consider breaking down complex queries into many simple queries and reducing the number of DISTINCT conditions. If the primary key column is part of the result set of the column, the DISTINCT condition may have no effect. `,
			Case:     "SELECT DISTINCT c.c_id,count(DISTINCT c.c_name),count(DISTINCT c.c_e),count(DISTINCT c.c_n),count(DISTINCT c.c_me),c.c_d FROM (select distinct id, name from B) as e WHERE e.country_id = c.country_id",
			Func:     (*Query4Audit).RuleDistinctUsage,
		},
		"DIS.002": {
			Item:     "DIS.002",
			Severity: "L3",
			Summary:  "COUNT(DISTINCT) when there are multiple columns, the result may be different from what you expected",
			Content:  `COUNT(DISTINCT col) Calculate the number of unique rows in this column except NULL. Note that COUNT(DISTINCT col, col2) If one of the columns is all NULL, then even if the other column has a different value, it will return 0. `,
			Case:     "SELECT COUNT(DISTINCT col, col2) FROM tbl;",
			Func:     (*Query4Audit).RuleCountDistinctMultiCol,
		},
		// DIS.003 灵感来源于如下链接
		// http://www.ijstr.org/final-print/oct2015/Query-Optimization-Techniques-Tips-For-Writing-Efficient-And-Faster-Sql-Queries.pdf
		"DIS.003": {
			Item:     "DIS.003",
			Severity: "L3",
			Summary:  "DISTINCT * has no meaning for tables with primary keys",
			Content:  `When the table already has a primary key, the output result of DISTINCT for all columns is the same as the result of no DISTINCT operation, please don't superfluous. `,
			Case:     "SELECT DISTINCT * FROM film;",
			Func:     (*Query4Audit).RuleDistinctStar,
		},
		"FUN.001": {
			Item:     "FUN.001",
			Severity: "L2",
			Summary:  "Avoid using functions or other operators in WHERE conditions",
			Content:  `Although the use of functions in SQL can simplify many complex queries, queries that use functions cannot use the indexes that have been established in the table. The query will be a full table scan and the performance will be poor. It is usually recommended to write the column name on the left side of the comparison operator, and put the query filter condition on the right side of the comparison operator. It is also not recommended to write extra parentheses on both sides of the query and comparison conditions, which will cause greater confusion in reading. `,
			Case:     "select id from t where substring(name,1,3)='abc'",
			Func:     (*Query4Audit).RuleCompareWithFunction,
		},
		"FUN.002": {
			Item:     "FUN.002",
			Severity: "L1",
			Summary:  "When WHERE condition or non-MyISAM engine is specified, COUNT(*) operation performance is not good",
			Content:  `The function of COUNT(*) is to count the number of table rows, and the function of COUNT(COL) is to count the number of non-NULL rows in the specified column. MyISAM table is specially optimized for COUNT(*) to count the number of rows in the whole table, which is usually very fast. But for non-MyISAM tables or certain WHERE conditions are specified, the COUNT(*) operation needs to scan a large number of rows to obtain accurate results, and the performance is therefore not good. Sometimes certain business scenarios do not require a completely accurate COUNT value, and an approximate value can be used instead. The number of rows estimated by the optimizer from EXPLAIN is a good approximation. Executing EXPLAIN does not need to actually execute the query, so the cost is very low. `,
			Case:     "SELECT c3, COUNT(*) AS accounts FROM tab where c2 <10000 GROUP BY c3 ORDER BY num",
			Func:     (*Query4Audit).RuleCountStar,
		},
		"FUN.003": {
			Item:     "FUN.003",
			Severity: "L3",
			Summary:  "Used string concatenation merged into nullable columns",
			Content:  `In some query requests, you need to force a column or expression to return a non-NULL value, so that the query logic becomes simpler, but you don't want to save this value. You can use the COALESCE() function to construct a concatenated expression, so that even a null column does not make the entire expression NULL. `,
			Case:     "select c1 || coalesce(' '|| c2 ||'', '') || c3 as c from tbl",
			Func:     (*Query4Audit).RuleStringConcatenation,
		},
		"FUN.004": {
			Item:     "FUN.004",
			Severity: "L4",
			Summary:  "It is not recommended to use the SYSDATE() function",
			Content:  `SYSDATE() function may cause inconsistent master and slave data, please use NOW() function instead of SYSDATE(). `,
			Case:     "SELECT SYSDATE();",
			Func:     (*Query4Audit).RuleSysdate,
		},
		"FUN.005": {
			Item:     "FUN.005",
			Severity: "L1",
			Summary:  "It is not recommended to use COUNT(col) or COUNT(constant)",
			Content:  `Don't use COUNT(col) or COUNT(constant) instead of COUNT(*), COUNT(*) is the standard method of counting the number of rows defined by SQL92. It has nothing to do with data, and has nothing to do with NULL and non-NULL. `,
			Case:     "SELECT COUNT(1) FROM tbl;",
			Func:     (*Query4Audit).RuleCountConst,
		},
		"FUN.006": {
			Item:     "FUN.006",
			Severity: "L1",
			Summary:  "Pay attention to NPE issues when using SUM(COL)",
			Content:  `When the values ​​of a certain column are all NULL, the return result of COUNT(COL) is 0, but the return result of SUM(COL) is NULL, so you need to pay attention to the NPE problem when using SUM(). The following methods can be used to avoid the NPE problem of SUM: SELECT IF(ISNULL(SUM(COL)), 0, SUM(COL)) FROM tbl`,
			Case:     "SELECT SUM(COL) FROM tbl;",
			Func:     (*Query4Audit).RuleSumNPE,
		},
		"FUN.007": {
			Item:     "FUN.007",
			Severity: "L1",
			Summary:  "The use of triggers is not recommended",
			Content:  `There is no feedback and log for the execution of the trigger, which hides the actual execution steps. When there is a problem with the database, the specific execution of the trigger cannot be analyzed through the slow log, and the problem is not easy to find. In MySQL, triggers cannot be temporarily closed or opened. In scenarios such as data migration or data recovery, you need to drop triggers temporarily, which may affect the production environment. `,
			Case:     "CREATE TRIGGER t1 AFTER INSERT ON work FOR EACH ROW INSERT INTO time VALUES(NOW());",
			Func:     (*Query4Audit).RuleForbiddenTrigger,
		},
		"FUN.008": {
			Item:     "FUN.008",
			Severity: "L1",
			Summary:  "It is not recommended to use stored procedures",
			Content:  `The stored procedure has no version control, and it is difficult to achieve business unawareness with the upgrade of the stored procedure in conjunction with the business. Storage procedures also have problems in expansion and transplantation. `,
			Case:     "CREATE PROCEDURE simpleproc (OUT param1 INT);",
			Func:     (*Query4Audit).RuleForbiddenProcedure,
		},
		"FUN.009": {
			Item:     "FUN.009",
			Severity: "L1",
			Summary:  "It is not recommended to use custom functions",
			Content:  `It is not recommended to use custom functions`,
			Case:     "CREATE FUNCTION hello (s CHAR(20));",
			Func:     (*Query4Audit).RuleForbiddenFunction,
		},
		"GRP.001": {
			Item:     "GRP.001",
			Severity: "L2",
			Summary:  "It is not recommended to use GROUP BY for equivalent query columns",
			Content:  `The columns in GROUP BY used the equivalent query in the previous WHERE condition, so it doesn't make much sense to perform GROUP BY on such columns. `,
			Case:     "select film_id, title from film where release_year='2006' group by release_year",
			Func:     (*Query4Audit).RuleOK, // This suggestion is given to RuleGroupByConst in indexAdvisor
		},
		"JOI.001": {
			Item:     "JOI.001",
			Severity: "L2",
			Summary:  "JOIN statement mixes comma and ANSI mode",
			Content:  `Mixed comma and ANSI JOIN when joining tables are not easy for humans to understand, and different versions of MySQL have different table join behaviors and priorities. Errors may be introduced when the MySQL version changes. `,
			Case:     "select c1,c2,c3 from t1,t2 join t3 on t1.c1=t2.c1,t1.c3=t3,c1 where id>1000",
			Func:     (*Query4Audit).RuleCommaAnsiJoin,
		},
		"JOI.002": {
			Item:     "JOI.002",
			Severity: "L4",
			Summary:  "The same table is connected twice",
			Content:  `The same table appears at least twice in the FROM clause, which can be simplified to a single access to the table. `,
			Case:     "select tb1.col from (tb1, tb2) join tb2 on tb1.id=tb.id where tb1.id=1",
			Func:     (*Query4Audit).RuleDupJoin,
		},
		"JOI.003": {
			Item:     "JOI.003",
			Severity: "L4",
			Summary:  "OUTER JOIN is invalid",
			Content:  `Due to the wrong WHERE condition, no data is returned from the external table of OUTER JOIN, which will implicitly convert the query to INNER JOIN. Such as: select c from L left join R using(c) where L.a=5 and R.b=10. This kind of SQL logic may have errors or programmers may misunderstand how OUTER JOIN works, because LEFT/RIGHT JOIN is the abbreviation of LEFT/RIGHT OUTER JOIN. `,
			Case:     "select c1,c2,c3 from t1 left outer join t2 using(c1) where t1.c2=2 and t2.c3=4",
			Func:     (*Query4Audit).RuleOK, // TODO
		},
		"JOI.004": {
			Item:     "JOI.004",
			Severity: "L4",
			Summary:  "It is not recommended to use exclusive JOIN",
			Content:  `LEFT OUTER JOIN statement with WHERE clause only in the right table is NULL, it may be the wrong column in the WHERE clause, such as: "... FROM l LEFT OUTER JOIN r ON ll = rr WHERE rz IS NULL", the correct logic for this query may be WHERE rr IS NULL. `,
			Case:     "select c1,c2,c3 from t1 left outer join t2 on t1.c1=t2.c1 where t2.c2 is null",
			Func:     (*Query4Audit).RuleOK, // TODO
		},
		"JOI.005": {
			Item:     "JOI.005",
			Severity: "L2",
			Summary:  "Reduce the number of JOINs",
			Content:  `Too many JOINs are a symptom of a complex bound query. Consider breaking down complex queries into many simple queries and reducing the number of JOINs. `,
			Case:     "select bp1.p_id, b1.d_d as l, b1.b_id from b1 join bp1 on (b1.b_id = bp1.b_id) left outer join (b1 as b2 join bp2 on (b2.b_id = bp2.b_id) ) on (bp1.p_id = bp2.p_id) join bp21 on (b1.b_id = bp1.b_id) join bp31 on (b1.b_id = bp1.b_id) join bp41 on (b1.b_id = bp1.b_id) where b2. b_id = 0",
			Func:     (*Query4Audit).RuleReduceNumberOfJoin,
		},
		"JOI.006": {
			Item:     "JOI.006",
			Severity: "L4",
			Summary:  "Rewriting a nested query to JOIN usually leads to more efficient execution and more effective optimization",
			Content:  `Generally speaking, non-nested subqueries are always used for associative subqueries, at most from a table in the FROM clause. These subqueries are used for ANY, ALL and EXISTS predicates. If it can be determined based on the query semantics that the subquery returns at most one row, then an unrelated subquery or subquery from multiple tables in the FROM clause will be flattened. `,
			Case:     "SELECT s,p,d FROM tbl WHERE p.p_id = (SELECT s.p_id FROM tbl WHERE s.c_id = 100996 AND s.q = 1 )",
			Func:     (*Query4Audit).RuleNestedSubQueries,
		},
		"JOI.007": {
			Item:     "JOI.007",
			Severity: "L4",
			Summary:  "It is not recommended to delete or update associated tables",
			Content:  `When you need to delete or update multiple tables at the same time, it is recommended to use simple statements. One SQL only deletes or updates one table. Try not to combine the operations of multiple tables in the same statement. `,
			Case:     "UPDATE users u LEFT JOIN hobby h ON u.id = h.uid SET u.name ='pianoboy' WHERE h.hobby ='piano';",
			Func:     (*Query4Audit).RuleMultiDeleteUpdate,
		},
		"JOI.008": {
			Item:     "JOI.008",
			Severity: "L4",
			Summary:  "Don't use cross-database JOIN queries",
			Content:  `Generally speaking, a cross-database JOIN query means that the query statement spans two different subsystems, which may mean that the system coupling is too high or the library table structure design is unreasonable. `,
			Case:     "SELECT s,p,d FROM tbl WHERE p.p_id = (SELECT s.p_id FROM tbl WHERE s.c_id = 100996 AND s.q = 1 )",
			Func:     (*Query4Audit).RuleMultiDBJoin,
		},
		// TODO: Cross-database transaction check, SOAR has not dealt with the transaction at present理
		"KEY.001": {
			Item:     "KEY.001",
			Severity: "L2",
			Summary:  "It is recommended to use an auto-increment column as the primary key. If you use a joint auto-increment primary key, please use the auto-increment key as the first column",
			Content:  `It is recommended to use an auto-increment column as the primary key. If you use a joint auto-increment primary key, please use the auto-increment key as the first column.`,
			Case:     "create table test(`id` int(11) NOT NULL PRIMARY KEY (`id`))",
			Func:     (*Query4Audit).RulePKNotInt,
		},
		"KEY.002": {
			Item:     "KEY.002",
			Severity: "L4",
			Summary:  "There is no primary key or unique key, and the table structure cannot be changed online",
			Content:  `No primary key or unique key, table structure cannot be changed online`,
			Case:     "create table test(col varchar(5000))",
			Func:     (*Query4Audit).RuleNoOSCKey,
		},
		"KEY.003": {
			Item:     "KEY.003",
			Severity: "L4",
			Summary:  "Avoid recursive relationships such as foreign keys",
			Content:  `Data with recursive relationships is very common, and data is often organized like a tree or hierarchically. However, creating a foreign key constraint to enforce the relationship between two columns in the same table can lead to clumsy queries. Each level of the tree corresponds to another connection. You will need to issue a recursive query to get all descendants or all ancestors of the node. The solution is to construct an additional closure table. It records the relationship between all nodes in the tree, not just those that have a direct parent-child relationship. You can also compare different levels of data design: closure tables, path enumerations, nested sets. Then choose one according to the needs of the application. `,
			Case:     "CREATE TABLE tab2 (p_id BIGINT UNSIGNED NOT NULL,a_id BIGINT UNSIGNED NOT NULL,PRIMARY KEY (p_id, a_id),FOREIGN KEY (p_id) REFERENCES tab1(p_id),FOREIGN KEY (a_id) REFERENCES tab3(a_idENCE))",
			Func:     (*Query4Audit).RuleRecursiveDependency,
		},
		// TODO: Add a new composite index, whether the fields are sorted by scattered granularity from large to small, with the highest degree of discrimination on the left
		"KEY.004": {
			Item:     "KEY.004",
			Severity: "L0",
			Summary:  "Reminder: Please align the index attribute order with the query",
			Content:  `If you create a composite index for a column, please make sure that the order of the query attributes and index attributes is the same so that the DBMS can use the index when processing the query. If the query and index attribute orders are not aligned, the DBMS may not be able to use the index during query processing. `,
			Case:     "create index idx1 on tbl (last_name,first_name)",
			Func:     (*Query4Audit).RuleIndexAttributeOrder,
		},
		"KEY.005": {
			Item:     "KEY.005",
			Severity: "L2",
			Summary:  "Too many indexes are built on the table",
			Content:  `Table built too many indexes`,
			Case:     "CREATE TABLE tbl (a int, b int, c int, KEY idx_a (`a`),KEY idx_b(`b`),KEY idx_c(`c`));",
			Func:     (*Query4Audit).RuleTooManyKeys,
		},
		"KEY.006": {
			Item:     "KEY.006",
			Severity: "L4",
			Summary:  "Too many columns in the primary key",
			Content:  `Too many columns in primary key`,
			Case:     "CREATE TABLE tbl (a int, b int, c int, PRIMARY KEY(`a`,`b`,`c`));",
			Func:     (*Query4Audit).RuleTooManyKeyParts,
		},
		"KEY.007": {
			Item:     "KEY.007",
			Severity: "L4",
			Summary:  "The primary key is not specified or the primary key is not int or bigint",
			Content:  `The primary key is not specified or the primary key is not int or bigint. It is recommended to set the primary key to int unsigned or bigint unsigned. `,
			Case:     "CREATE TABLE tbl (a int);",
			Func:     (*Query4Audit).RulePKNotInt,
		},
		"KEY.008": {
			Item:     "KEY.008",
			Severity: "L4",
			Summary:  "ORDER BY multiple columns but different sorting directions may not be able to use the index",
			Content:  `Before MySQL 8.0, when multiple columns of ORDER BY specify different sorting directions, the established index cannot be used. `,
			Case:     "SELECT * FROM tbl ORDER BY a DESC, b ASC;",
			Func:     (*Query4Audit).RuleOrderByMultiDirection,
		},
		"KEY.009": {
			Item:     "KEY.009",
			Severity: "L0",
			Summary:  "Please check the data uniqueness before adding a unique index",
			Content:  `Please check the data uniqueness of the added unique index column in advance. If the data is not unique, the duplicate columns may be automatically deleted when the online table structure is adjusted, which may cause data loss. `,
			Case:     "CREATE UNIQUE INDEX part_of_name ON customer (name(10));",
			Func:     (*Query4Audit).RuleUniqueKeyDup,
		},
		"KEY.010": {
			Item:     "KEY.010",
			Severity: "L0",
			Summary:  "Full-text indexing is not a silver bullet",
			Content:  `Full-text index is mainly used to solve the performance problem of fuzzy query, but it is necessary to control the frequency and concurrency of the query. At the same time, pay attention to adjust the ft_min_word_len, ft_max_word_len, ngram_token_size and other parameters. `,
			Case:     "CREATE TABLE `tb` (`id` int(10) unsigned NOT NULL AUTO_INCREMENT, `ip` varchar(255) NOT NULL DEFAULT'', PRIMARY KEY (`id`), FULLTEXT KEY `ip` (`ip `)) ENGINE=InnoDB;",
			Func:     (*Query4Audit).RuleFulltextIndex,
		},
		"KWR.001": {
			Item:     "KWR.001",
			Severity: "L2",
			Summary:  "SQL_CALC_FOUND_ROWS is inefficient",
			Content:  `Because SQL_CALC_FOUND_ROWS can't scale well, it may cause performance problems; it is recommended that the business use other strategies to replace the counting function provided by SQL_CALC_FOUND_ROWS, such as: paging results display, etc. `,
			Case:     "select SQL_CALC_FOUND_ROWS col from tbl where id>1000",
			Func:     (*Query4Audit).RuleSQLCalcFoundRows,
		},
		"KWR.002": {
			Item:     "KWR.002",
			Severity: "L2",
			Summary:  "It is not recommended to use MySQL keywords as column names or table names",
			Content:  `When using keywords as column names or table names, the program needs to escape the column names and table names. If negligence is caused, the request cannot be executed. `,
			Case:     "CREATE TABLE tbl (`select` int )",
			Func:     (*Query4Audit).RuleUseKeyWord,
		},
		"KWR.003": {
			Item:     "KWR.003",
			Severity: "L1",
			Summary:  "It is not recommended to use plural numbers as column names or table names",
			Content:  `The name of the table should only indicate the content of the entity in the table, not the number of entities, and the corresponding DO class name is also in singular form, which conforms to the expression habit. `,
			Case:     "CREATE TABLE tbl (`books` int )",
			Func:     (*Query4Audit).RulePluralWord,
		},
		"KWR.004": {
			Item:     "KWR.004",
			Severity: "L1",
			Summary:  "It is not recommended to use multi-byte encoded characters (Chinese) for naming",
			Content:  `It is recommended to use English, numbers, underscores and other characters when naming libraries, tables, columns, and aliases. Chinese or other multi-byte encoded characters are not recommended. `,
			Case:     "select col as column from tb",
			Func:     (*Query4Audit).RuleMultiBytesWord,
		},
		"KWR.005": {
			Item:     "KWR.005",
			Severity: "L1",
			Summary:  "SQL contains unicode special characters",
			Content:  "Some IDEs will automatically insert unicode characters invisible to the naked eye in SQL. Such as: non-break space, zero-width space, etc. Under Linux, you can use the `cat -A file.sql` command to view invisible characters.",
			Case:     "update tb set status = 1 where id = 1;",
			Func:     (*Query4Audit).RuleInvisibleUnicode,
		},
		"LCK.001": {
			Item:     "LCK.001",
			Severity: "L3",
			Summary:  "INSERT INTO xx SELECT has large locking granularity, please be cautious",
			Content:  `INSERT INTO xx SELECT lock granularity is large, please be careful`,
			Case:     "INSERT INTO tbl SELECT * FROM tbl2;",
			Func:     (*Query4Audit).RuleInsertSelect,
		},
		"LCK.002": {
			Item:     "LCK.002",
			Severity: "L3",
			Summary:  "Please use INSERT ON DUPLICATE KEY UPDATE with caution",
			Content:  `Using INSERT ON DUPLICATE KEY UPDATE when the primary key is an auto-increment key may cause a large number of discontinuous and rapid growth of the primary key, resulting in rapid overflow of the primary key and unable to continue writing. In extreme cases, the master-slave data may be inconsistent. `,
			Case:     "INSERT INTO t1(a,b,c) VALUES (1,2,3) ON DUPLICATE KEY UPDATE c=c+1;",
			Func:     (*Query4Audit).RuleInsertOnDup,
		},
		"LIT.001": {
			Item:     "LIT.001",
			Severity: "L2",
			Summary:  "Use character type to store IP address",
			Content:  `The string literally looks like an IP address, but it is not a parameter of INET_ATON(), indicating that the data is stored as characters instead of integers. It is more efficient to store the IP address as an integer. `,
			Case:     "insert into tbl (IP,name) values('10.20.306.122','test')",
			Func:     (*Query4Audit).RuleIPString,
		},
		"LIT.002": {
			Item:     "LIT.002",
			Severity: "L4",
			Summary:  "The date/time is not enclosed in quotation marks",
			Content:  `Query such as "WHERE col <2010-02-12" is valid SQL, but it may be an error because it will be interpreted as "WHERE col <1996"; date/time text should be quoted. `,
			Case:     "select col1,col2 from tbl where time <2018-01-10",
			Func:     (*Query4Audit).RuleDataNotQuote,
		},
		"LIT.003": {
			Item:     "LIT.003",
			Severity: "L3",
			Summary:  "A collection of related data stored in a column",
			Content:  `Store the ID as a list as a VARCHAR/TEXT column, which can cause performance and data integrity issues. Querying such columns requires the use of pattern matching expressions. Using a comma-separated list to do a multi-table join query to locate a row of data is extremely inelegant and time-consuming. This will make it more difficult to verify the ID. Consider, how much data can the list support at most? Store IDs in a separate table instead of using multi-valued attributes, so that each individual attribute value can occupy a row. In this way, the cross table realizes the many-to-many relationship between the two tables. This will simplify the query better and verify the ID more effectively. `,
			Case:     "select c1,c2,c3,c4 from tab1 where col_id REGEXP'[[:<:]]12[[:>:]]'",
			Func:     (*Query4Audit).RuleMultiValueAttribute,
		},
		"LIT.004": {
			Item:     "LIT.004",
			Severity: "L1",
			Summary:  "Please use a semicolon or the set DELIMITER ending",
			Content:  `USE database, SHOW DATABASES and other commands also need to end with a semicolon or the set DELIMITER. `,
			Case:     "USE db",
			Func:     (*Query4Audit).RuleOK, // TODO: RuleAddDelimiter
		},
		"RES.001": {
			Item:     "RES.001",
			Severity: "L4",
			Summary:  "Indeterministic GROUP BY",
			Content:  `The column returned by SQL is neither in the aggregate function nor in the column of the GROUP BY expression, so the result of these values ​​will be non-deterministic. For example: select a, b, c from tbl where foo="bar" group by a, the result returned by the SQL is uncertain. `,
			Case:     "select c1,c2,c3 from t1 where c2='foo' group by c2",
			Func:     (*Query4Audit).RuleNoDeterministicGroupby,
		},
		"RES.002": {
			Item:     "RES.002",
			Severity: "L4",
			Summary:  "LIMIT query without ORDER BY",
			Content:  `LIMIT without ORDER BY will lead to non-deterministic results, depending on the query execution plan. `,
			Case:     "select col1,col2 from tbl where name=xx limit 10",
			Func:     (*Query4Audit).RuleNoDeterministicLimit,
		},
		"RES.003": {
			Item:     "RES.003",
			Severity: "L4",
			Summary:  "UPDATE/DELETE operation uses LIMIT conditions",
			Content:  `UPDATE/DELETE operation using LIMIT condition is as dangerous as not adding WHERE condition, it may cause inconsistency of master-slave data or interruption of slave database synchronization. `,
			Case:     "UPDATE film SET length = 120 WHERE title ='abc' LIMIT 1;",
			Func:     (*Query4Audit).RuleUpdateDeleteWithLimit,
		},
		"RES.004": {
			Item:     "RES.004",
			Severity: "L4",
			Summary:  "UPDATE/DELETE operation specifies the ORDER BY condition",
			Content:  `Do not specify ORDER BY conditions for UPDATE/DELETE operations. `,
			Case:     "UPDATE film SET length = 120 WHERE title ='abc' ORDER BY title",
			Func:     (*Query4Audit).RuleUpdateDeleteWithOrderby,
		},
		"RES.005": {
			Item:     "RES.005",
			Severity: "L4",
			Summary:  "There may be logic errors in the UPDATE statement, resulting in data corruption",
			Content:  "In an UPDATE statement, if you want to update multiple fields, you cannot use AND between the fields, but should be separated by commas.",
			Case:     "update tbl set col = 1 and cl = 2 where col=3;",
			Func:     (*Query4Audit).RuleUpdateSetAnd,
		},
		"RES.006": {
			Item:     "RES.006",
			Severity: "L4",
			Summary:  "Never really compare conditions",
			Content:  "The query condition is never true. If the condition appears in where, it may cause the query to have no matching results.",
			Case:     "select * from tbl where 1 != 1;",
			Func:     (*Query4Audit).RuleImpossibleWhere,
		},
		"RES.007": {
			Item:     "RES.007",
			Severity: "L4",
			Summary:  "Comparison condition is always true",
			Content:  "The query condition is always true, which may cause the WHERE condition to become invalid for full table query.",
			Case:     "select * from tbl where 1 = 1;",
			Func:     (*Query4Audit).RuleMeaninglessWhere,
		},
		"RES.008": {
			Item:     "RES.008",
			Severity: "L2",
			Summary:  "It is not recommended to use LOAD DATA/SELECT ... INTO OUTFILE",
			Content:  "SELECT INTO OUTFILE needs to be granted FILE permission, which will introduce security issues. Although LOAD DATA can increase the speed of data import, it may also cause excessive delay in synchronization from the library.",
			Case:     "LOAD DATA INFILE'data.txt' INTO TABLE db2.my_table;",
			Func:     (*Query4Audit).RuleLoadFile,
		},
		"RES.009": {
			Item:     "RES.009",
			Severity: "L2",
			Summary:  "Continuous judgment is not recommended",
			Content:  "Similar to this SELECT * FROM tbl WHERE col = col ='abc' statement may be a writing error, the meaning you may want to express is col ='abc'. If it is indeed a business requirement, it is recommended to modify it to col = col and col ='abc'.",
			Case:     "SELECT * FROM tbl WHERE col = col ='abc'",
			Func:     (*Query4Audit).RuleMultiCompare,
		},
		"RES.010": {
			Item:     "RES.010",
			Severity: "L2",
			Summary:  "The field defined as ON UPDATE CURRENT_TIMESTAMP in the table building statement is not recommended to contain business logic",
			Content:  "The field defined as ON UPDATE CURRENT_TIMESTAMP will be modified when other fields of the table are updated. If it contains business logic, the user will see hidden dangers. If you modify the data in batches but do not want to modify the field, it will cause data errors. ",
			Case:     `CREATE TABLE category (category_id TINYINT UNSIGNED NOT NULL AUTO_INCREMENT, name VARCHAR(25) NOT NULL, last_update TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, PRIMARY KEY (category_id)`,
			Func:     (*Query4Audit).RuleCreateOnUpdate,
		},
		"RES.011": {
			Item:     "RES.011",
			Severity: "L2",
			Summary:  "The table of the update request operation contains the ON UPDATE CURRENT_TIMESTAMP field",
			Content:  "The field defined as ON UPDATE CURRENT_TIMESTAMP will be modified when other fields in the table are updated. Please check. If you don’t want to modify the update time of the field, you can use the following method: UPDATE category SET name='ActioN', last_update=last_update WHERE category_id=1",
			Case:     "UPDATE category SET name='ActioN', last_update=last_update WHERE category_id=1",
			Func:     (*Query4Audit).RuleOK, // It is recommended to give RuleUpdateOnUpdate in indexAdvisor
		},
		"SEC.001": {
			Item:     "SEC.001",
			Severity: "L0",
			Summary:  "Please use TRUNCATE operation with caution",
			Content:  `Generally speaking, the fastest way to empty a table is to use the TRUNCATE TABLE tbl_name; statement. However, the TRUNCATE operation is not without cost. TRUNCATE TABLE cannot return the exact number of deleted rows. If you need to return the number of deleted rows, it is recommended to use DELETE syntax. TRUNCATE operation will also reset AUTO_INCREMENT, if you don't want to reset the value, it is recommended to use DELETE FROM tbl_name WHERE 1; instead. The TRUNCATE operation will add source data locks (MDL) to the data dictionary. When TRUNCATE many tables are required at one time, it will affect all requests of the entire instance. Therefore, if you want to TRUNCATE multiple tables, it is recommended to use DROP+CREATE to reduce the lock duration. `,
			Case:     "TRUNCATE TABLE tbl_name",
			Func:     (*Query4Audit).RuleTruncateTable,
		},
		"SEC.002": {
			Item:     "SEC.002",
			Severity: "L0",
			Summary:  "Do not store passwords in clear text",
			Content:  `It is not safe to store passwords in plain text or to transmit passwords in plain text on the network. If an attacker can intercept the SQL statement you use to insert the password, they can read the password directly. In addition, inserting the string entered by the user into a pure SQL statement in plaintext will also allow the attacker to discover it. If you can read the password, so can a hacker. The solution is to use a one-way hash function to encrypt the original password. Hashing refers to a function that transforms an input string into another new, unrecognizable string. Add a random string to the password encryption expression to defend against "dictionary attacks." Do not enter the plaintext password into the SQL query statement. Calculate the hash string in the application code, and only use the hash string in the SQL query. `,
			Case:     "create table test(id int,name varchar(20) not null,password varchar(200)not null)",
			Func:     (*Query4Audit).RuleReadablePasswords,
		},
		"SEC.003": {
			Item:     "SEC.003",
			Severity: "L0",
			Summary:  "Pay attention to backup when using DELETE/DROP/TRUNCATE and other operations",
			Content:  `It is necessary to back up data before performing high-risk operations. `,
			Case:     "delete from table where col ='condition'",
			Func:     (*Query4Audit).RuleDataDrop,
		},
		"SEC.004": {
			Item:     "SEC.004",
			Severity: "L0",
			Summary:  "Found common SQL injection functions",
			Content:  `SLEEP(), BENCHMARK(), GET_LOCK(), RELEASE_LOCK() and other functions usually appear in SQL injection statements, which will seriously affect database performance. `,
			Case:     "SELECT BENCHMARK(10, RAND())",
			Func:     (*Query4Audit).RuleInjection,
		},
		"STA.001": {
			Item:     "STA.001",
			Severity: "L0",
			Summary:  "'!=' operator is non-standard",
			Content:  `"<>" is the inequality operator in standard SQL. `,
			Case:     "select col1,col2 from tbl where type!=0",
			Func:     (*Query4Audit).RuleStandardINEQ,
		},
		"STA.002": {
			Item:     "STA.002",
			Severity: "L1",
			Summary:  "It is recommended not to add spaces after the dot of the library name or table name",
			Content:  `When using the db.table or table.column format to access a table or field, please do not add a space after the dot, although the syntax is correct. `,
			Case:     "select col from sakila. film",
			Func:     (*Query4Audit).RuleSpaceAfterDot,
		},
		"STA.003": {
			Item:     "STA.003",
			Severity: "L1",
			Summary:  "The index naming is not standardized",
			Content:  `It is recommended that the common secondary index be prefixed with ` + common.Config.IdxPrefix + `, and the unique index should be prefixed with` + common.Config.UkPrefix + `. `,
			Case:     "select col from now where type!=0",
			Func:     (*Query4Audit).RuleIdxPrefix,
		},
		"STA.004": {
			Item:     "STA.004",
			Severity: "L1",
			Summary:  "Please do not use characters other than letters, numbers and underscores when naming",
			Content:  `Start with a letter or underscore. Only letters, numbers and underscores are allowed in the name. Please unify capitalization and do not use camel case nomenclature. Do not use consecutive underscores'__' in the name, as it is difficult to recognize. `,
			Case:     "CREATE TABLE `abc` (a int);",
			Func:     (*Query4Audit).RuleStandardName,
		},
		"SUB.001": {
			Item:     "SUB.001",
			Severity: "L4",
			Summary:  "MySQL has a poor optimization effect on subqueries",
			Content:  `MySQL executes a subquery with each row in the external query as a dependent subquery. This is a common cause of severe performance problems. This may be improved in MySQL 5.6 version, but for 5.1 and earlier versions, it is recommended to rewrite this type of query as JOIN or LEFT OUTER JOIN respectively. `,
			Case:     "select col1,col2,col3 from table1 where col2 in(select col from table2)",
			Func:     (*Query4Audit).RuleInSubquery,
		},
		"SUB.002": {
			Item:     "SUB.002",
			Severity: "L2",
			Summary:  "If you don't care about duplication, it is recommended to use UNION ALL instead of UNION",
			Content:  `Unlike UNION which removes duplicates, UNION ALL allows duplicate tuples. If you don't care about repeated tuples, then using UNION ALL will be a faster option. `,
			Case:     "select teacher_id as id,people_name as name from t1,t2 where t1.teacher_id=t2.people_id union select student_id as id,people_name as name from t1,t2 where t1.student_id=t2.people_id",
			Func:     (*Query4Audit).RuleUNIONUsage,
		},
		"SUB.003": {
			Item:     "SUB.003",
			Severity: "L3",
			Summary:  "Consider using EXISTS instead of DISTINCT subqueries",
			Content:  `DISTINCT keyword deletes duplicates after sorting tuples. Instead, consider using a subquery with the EXISTS keyword, you can avoid returning the entire table. `,
			Case:     "SELECT DISTINCT c.c_id, c.c_name FROM c,e WHERE e.c_id = c.c_id",
			Func:     (*Query4Audit).RuleDistinctJoinUsage,
		},
		// TODO: 5.6有了semi join 还要把 in 转成 exists 么？
		// Use EXISTS instead of IN to check existence of data.
		// http://www.winwire.com/25-tips-to-improve-sql-query-performance/
		"SUB.004": {
			Item:     "SUB.004",
			Severity: "L3",
			Summary:  "The nested connection depth in the execution plan is too deep",
			Content:  `MySQL's optimization effect on sub-queries is not good. MySQL will execute sub-queries as dependent sub-queries for each row in the external query. This is a common cause of severe performance problems. `,
			Case:     "SELECT * from tb where id in (select id from (select id from tb))",
			Func:     (*Query4Audit).RuleSubqueryDepth,
		},
		// SUB.005灵感来自 https://blog.csdn.net/zhuocr/article/details/61192418
		"SUB.005": {
			Item:     "SUB.005",
			Severity: "L8",
			Summary:  "Subqueries do not support LIMIT",
			Content:  `The current MySQL version does not support'LIMIT & IN/ALL/ANY/SOME' in sub-queries. `,
			Case:     "SELECT * FROM staff WHERE name IN (SELECT NAME FROM customer ORDER BY name LIMIT 1)",
			Func:     (*Query4Audit).RuleSubQueryLimit,
		},
		"SUB.006": {
			Item:     "SUB.006",
			Severity: "L2",
			Summary:  "It is not recommended to use functions in subqueries",
			Content:  `MySQL takes each row in the external query as a dependent subquery to execute a subquery. If a function is used in the subquery, it is difficult to perform an efficient query even with a semi-join. You can rewrite the subquery as an OUTER JOIN statement and filter the data with join conditions. `,
			Case:     "SELECT * FROM staff WHERE name IN (SELECT max(NAME) FROM customer)",
			Func:     (*Query4Audit).RuleSubQueryFunctions,
		},
		"SUB.007": {
			Item:     "SUB.007",
			Severity: "L2",
			Summary:  "For UNION joint queries with LIMIT output restrictions on the outer layer, it is recommended to add LIMIT output restrictions for the inner query.",
			Content:  `Sometimes MySQL cannot "push down" the restriction conditions from the outer layer to the inner layer, which will make the conditions that could restrict the partial return results unable to be applied to the optimization of the inner query. For example: (SELECT * FROM tb1 ORDER BY name) UNION ALL (SELECT * FROM tb2 ORDER BY name) LIMIT 20; MySQL will put the results of the two sub-queries in a temporary table, and then take out 20 results, which can be passed in the two LIMIT 20 is added to each subquery to reduce the data in the temporary table. (SELECT * FROM tb1 ORDER BY name LIMIT 20) UNION ALL (SELECT * FROM tb2 ORDER BY name LIMIT 20) LIMIT 20;`,
			Case:     "(SELECT * FROM tb1 ORDER BY name LIMIT 20) UNION ALL (SELECT * FROM tb2 ORDER BY name LIMIT 20) LIMIT 20;",
			Func:     (*Query4Audit).RuleUNIONLimit,
		},
		"TBL.001": {
			Item:     "TBL.001",
			Severity: "L4",
			Summary:  "Partition table is not recommended",
			Content:  `Partition table is not recommended`,
			Case:     "CREATE TABLE trb3(id INT, name VARCHAR(50), purchased DATE) PARTITION BY RANGE(YEAR(purchased)) (PARTITION p0 VALUES LESS THAN (1990), PARTITION p1 VALUES LESS THAN (1995), PARTITION p2 VALUES LESS THAN (2000), PARTITION p3 VALUES LESS THAN (2005) );",
			Func:     (*Query4Audit).RulePartitionNotAllowed,
		},
		"TBL.002": {
			Item:     "TBL.002",
			Severity: "L4",
			Summary:  "Please select the appropriate storage engine for the table",
			Content:  `It is recommended to use the recommended storage engine when creating a table or modifying the storage engine of a table, such as: ` + strings.Join(common.Config.AllowEngines, ","),
			Case:     "create table test(`id` int(11) NOT NULL AUTO_INCREMENT)",
			Func:     (*Query4Audit).RuleAllowEngine,
		},
		"TBL.003": {
			Item:     "TBL.003",
			Severity: "L8",
			Summary:  "The table named DUAL has a special meaning in the database",
			Content:  `DUAL table is a virtual table, you don't need to create it to use it, and it is not recommended that the service name the table with DUAL. `,
			Case:     "create table dual(id int, primary key (id));",
			Func:     (*Query4Audit).RuleCreateDualTable,
		},
		"TBL.004": {
			Item:     "TBL.004",
			Severity: "L2",
			Summary:  "The initial AUTO_INCREMENT value of the table is not 0",
			Content:  `AUTO_INCREMENT is not 0 will cause data holes. `,
			Case:     "CREATE TABLE tbl (a int) AUTO_INCREMENT = 10;",
			Func:     (*Query4Audit).RuleAutoIncrementInitNotZero,
		},
		"TBL.005": {
			Item:     "TBL.005",
			Severity: "L4",
			Summary:  "Please use the recommended character set",
			Content:  `The table character set is only allowed to be set to'` + strings.Join(common.Config.AllowCharsets, ",") + "'",
			Case:     "CREATE TABLE tbl (a int) DEFAULT CHARSET = latin1;",
			Func:     (*Query4Audit).RuleTableCharsetCheck,
		},
		"TBL.006": {
			Item:     "TBL.006",
			Severity: "L1",
			Summary:  "View is not recommended",
			Content:  `View is not recommended`,
			Case:     "create view v_today (today) AS SELECT CURRENT_DATE;",
			Func:     (*Query4Audit).RuleForbiddenView,
		},
		"TBL.007": {
			Item:     "TBL.007",
			Severity: "L1",
			Summary:  "It is not recommended to use temporary tables",
			Content:  `Temporary tables are not recommended`,
			Case:     "CREATE TEMPORARY TABLE `work` (`time` time DEFAULT NULL) ENGINE=InnoDB;",
			Func:     (*Query4Audit).RuleForbiddenTempTable,
		},
		"TBL.008": {
			Item:     "TBL.008",
			Severity: "L4",
			Summary:  "Please use the recommended COLLATE",
			Content:  `COLLATE is only allowed to be set to'` + strings.Join(common.Config.AllowCollates, ",") + "'",
			Case:     "CREATE TABLE tbl (a int) DEFAULT COLLATE = latin1_bin;",
			Func:     (*Query4Audit).RuleTableCharsetCheck,
		},
	}
}

// IsIgnoreRule 判断是否是过滤规则
// 支持XXX*前缀匹配，OK规则不可设置过滤
func IsIgnoreRule(item string) bool {

	for _, ir := range common.Config.IgnoreRules {
		ir = strings.Trim(ir, "*")
		if strings.HasPrefix(item, ir) && ir != "OK" && ir != "" {
			common.Log.Debug("IsIgnoreRule: %s", item)
			return true
		}
	}
	return false
}

// InBlackList 判断一条请求是否在黑名单列表中
// 如果在返回true，表示不需要评审
// 注意这里没有做指纹判断，是否用指纹在这个函数的外面处理
func InBlackList(sql string) bool {
	in := false
	for _, r := range common.BlackList {
		if sql == r {
			in = true
			break
		}
		re, err := regexp.Compile("(?i)" + r)
		if err == nil {
			if re.FindString(sql) != "" {
				common.Log.Debug("InBlackList: true, regexp: %s, sql: %s", "(?i)"+r, sql)
				in = true
				break
			}
			common.Log.Debug("InBlackList: false, regexp: %s, sql: %s", "(?i)"+r, sql)
		}
	}
	return in
}

// FormatSuggest 格式化输出优化建议
func FormatSuggest(sql string, currentDB string, format string, suggests ...map[string]Rule) (map[string]Rule, string) {
	common.Log.Debug("FormatSuggest, Query: %s", sql)
	var fingerprint, id string
	var buf []string
	var score = 100
	type Result struct {
		ID          string
		Fingerprint string
		Sample      string
		Suggest     map[string]Rule
	}

	// 生成指纹和ID
	if sql != "" {
		fingerprint = query.Fingerprint(sql)
		id = query.Id(fingerprint)
	}

	// 合并重复的建议
	suggest := make(map[string]Rule)
	for _, s := range suggests {
		for item, rule := range s {
			suggest[item] = rule
		}
	}
	suggest = MergeConflictHeuristicRules(suggest)

	// 是否忽略显示OK建议，测试的时候大家都喜欢看OK，线上跑起来的时候OK太多反而容易看花眼
	ignoreOK := false
	for _, r := range common.Config.IgnoreRules {
		if "OK" == r {
			ignoreOK = true
		}
	}

	// 先保证suggest中有元素，然后再根据ignore配置删除不需要的项
	if len(suggest) < 1 {
		suggest = map[string]Rule{"OK": HeuristicRules["OK"]}
	}
	if ignoreOK || len(suggest) > 1 {
		delete(suggest, "OK")
	}
	for k := range suggest {
		if IsIgnoreRule(k) {
			delete(suggest, k)
		}
	}
	common.Log.Debug("FormatSuggest, format: %s", format)
	switch format {
	case "json":
		buf = append(buf, formatJSON(sql, currentDB, suggest))

	case "text":
		for item, rule := range suggest {
			buf = append(buf, fmt.Sprintln("Query: ", sql))
			buf = append(buf, fmt.Sprintln("ID: ", id))
			buf = append(buf, fmt.Sprintln("Item: ", item))
			buf = append(buf, fmt.Sprintln("Severity: ", rule.Severity))
			buf = append(buf, fmt.Sprintln("Summary: ", rule.Summary))
			buf = append(buf, fmt.Sprintln("Content: ", rule.Content))
		}
	case "lint":
		for item, rule := range suggest {
			// lint 中无需关注 OK 和 EXP
			if item != "OK" && !strings.HasPrefix(item, "EXP") {
				buf = append(buf, fmt.Sprintf("%s %s", item, rule.Summary))
			}
		}

	case "markdown", "html", "explain-digest", "duplicate-key-checker":
		if sql != "" && len(suggest) > 0 {
			switch common.Config.ExplainSQLReportType {
			case "fingerprint":
				buf = append(buf, fmt.Sprintf("# Query: %s\n", id))
				buf = append(buf, fmt.Sprintf("```sql\n%s\n```\n", fingerprint))
			case "sample":
				buf = append(buf, fmt.Sprintf("# Query: %s\n", id))
				buf = append(buf, fmt.Sprintf("```sql\n%s\n```\n", sql))
			default:
				buf = append(buf, fmt.Sprintf("# Query: %s\n", id))
				buf = append(buf, fmt.Sprintf("```sql\n%s\n```\n", ast.Pretty(sql, format)))
			}
		}
		// MySQL
		common.Log.Debug("FormatSuggest, start of sortedMySQLSuggest")
		var sortedMySQLSuggest []string
		for item := range suggest {
			if strings.HasPrefix(item, "ERR") {
				if suggest[item].Content == "" {
					delete(suggest, item)
				} else {
					sortedMySQLSuggest = append(sortedMySQLSuggest, item)
				}
			}
		}
		sort.Strings(sortedMySQLSuggest)
		if len(sortedMySQLSuggest) > 0 {
			buf = append(buf, "## MySQL execute failed\n")
		}
		for _, item := range sortedMySQLSuggest {
			buf = append(buf, fmt.Sprintln(suggest[item].Content))
			score = 0
			delete(suggest, item)
		}

		// Explain
		common.Log.Debug("FormatSuggest, start of sortedExplainSuggest")
		if suggest["EXP.000"].Item != "" {
			buf = append(buf, fmt.Sprintln("## ", suggest["EXP.000"].Summary))
			buf = append(buf, fmt.Sprintln(suggest["EXP.000"].Content))
			buf = append(buf, fmt.Sprint(suggest["EXP.000"].Case, "\n"))
			delete(suggest, "EXP.000")
		}
		var sortedExplainSuggest []string
		for item := range suggest {
			if strings.HasPrefix(item, "EXP") {
				sortedExplainSuggest = append(sortedExplainSuggest, item)
			}
		}
		sort.Strings(sortedExplainSuggest)
		for _, item := range sortedExplainSuggest {
			buf = append(buf, fmt.Sprintln("### ", suggest[item].Summary))
			buf = append(buf, fmt.Sprintln(suggest[item].Content))
			buf = append(buf, fmt.Sprint(suggest[item].Case, "\n"))
		}

		// Profiling
		common.Log.Debug("FormatSuggest, start of sortedProfilingSuggest")
		var sortedProfilingSuggest []string
		for item := range suggest {
			if strings.HasPrefix(item, "PRO") {
				sortedProfilingSuggest = append(sortedProfilingSuggest, item)
			}
		}
		sort.Strings(sortedProfilingSuggest)
		if len(sortedProfilingSuggest) > 0 {
			buf = append(buf, "## Profiling信息\n")
		}
		for _, item := range sortedProfilingSuggest {
			buf = append(buf, fmt.Sprintln(suggest[item].Content))
			delete(suggest, item)
		}

		// Trace
		common.Log.Debug("FormatSuggest, start of sortedTraceSuggest")
		var sortedTraceSuggest []string
		for item := range suggest {
			if strings.HasPrefix(item, "TRA") {
				sortedTraceSuggest = append(sortedTraceSuggest, item)
			}
		}
		sort.Strings(sortedTraceSuggest)
		if len(sortedTraceSuggest) > 0 {
			buf = append(buf, "## Trace信息\n")
		}
		for _, item := range sortedTraceSuggest {
			buf = append(buf, fmt.Sprintln(suggest[item].Content))
			delete(suggest, item)
		}

		// Index
		common.Log.Debug("FormatSuggest, start of sortedIdxSuggest")
		var sortedIdxSuggest []string
		for item := range suggest {
			if strings.HasPrefix(item, "IDX") {
				sortedIdxSuggest = append(sortedIdxSuggest, item)
			}
		}
		sort.Strings(sortedIdxSuggest)
		for _, item := range sortedIdxSuggest {
			buf = append(buf, fmt.Sprintln("## ", common.MarkdownEscape(suggest[item].Summary)))
			buf = append(buf, fmt.Sprintln("* **Item:** ", item))
			buf = append(buf, fmt.Sprintln("* **Severity:** ", suggest[item].Severity))
			minus, err := strconv.Atoi(strings.Trim(suggest[item].Severity, "L"))
			if err == nil {
				score = score - minus*5
			} else {
				common.Log.Debug("FormatSuggest, sortedIdxSuggest, strconv.Atoi, Error: ", err)
				score = 0
			}
			buf = append(buf, fmt.Sprintln("* **Content:** ", common.MarkdownEscape(suggest[item].Content)))

			if format == "duplicate-key-checker" {
				buf = append(buf, fmt.Sprintf("* **原建表语句:** \n```sql\n%s\n```\n", suggest[item].Case), "\n\n")
			} else {
				buf = append(buf, fmt.Sprint("* **Case:** ", common.MarkdownEscape(suggest[item].Case), "\n\n"))
			}
		}

		// Heuristic
		common.Log.Debug("FormatSuggest, start of sortedHeuristicSuggest")
		var sortedHeuristicSuggest []string
		for item := range suggest {
			if !strings.HasPrefix(item, "EXP") &&
				!strings.HasPrefix(item, "IDX") &&
				!strings.HasPrefix(item, "PRO") {
				sortedHeuristicSuggest = append(sortedHeuristicSuggest, item)
			}
		}
		sort.Strings(sortedHeuristicSuggest)
		for _, item := range sortedHeuristicSuggest {
			buf = append(buf, fmt.Sprintln("##", suggest[item].Summary))
			if item == "OK" {
				continue
			}
			buf = append(buf, fmt.Sprintln("* **Item:** ", item))
			buf = append(buf, fmt.Sprintln("* **Severity:** ", suggest[item].Severity))
			minus, err := strconv.Atoi(strings.Trim(suggest[item].Severity, "L"))
			if err == nil {
				score = score - minus*5
			} else {
				common.Log.Debug("FormatSuggest, sortedHeuristicSuggest, strconv.Atoi, Error: ", err)
				score = 0
			}
			buf = append(buf, fmt.Sprintln("* **Content:** ", common.MarkdownEscape(suggest[item].Content)))
			// buf = append(buf, fmt.Sprint("* **Case:** ", common.MarkdownEscape(suggest[item].Case), "\n\n"))
		}

	default:
		common.Log.Debug("report-type: %s", format)
		buf = append(buf, fmt.Sprintln("Query: ", sql))
		for _, rule := range suggest {
			buf = append(buf, pretty.Sprint(rule))
		}
	}

	// 打分
	var str string
	switch common.Config.ReportType {
	case "markdown", "html":
		if len(buf) > 1 {
			str = buf[0] + "\n" + common.Score(score) + "\n\n" + strings.Join(buf[1:], "\n")
		}
	default:
		str = strings.Join(buf, "\n")
	}

	return suggest, str
}

// JSONSuggest json format suggestion
type JSONSuggest struct {
	ID             string   `json:"ID"`
	Fingerprint    string   `json:"Fingerprint"`
	Score          int      `json:"Score"`
	Sample         string   `json:"Sample"`
	Explain        []Rule   `json:"Explain"`
	HeuristicRules []Rule   `json:"HeuristicRules"`
	IndexRules     []Rule   `json:"IndexRules"`
	Tables         []string `json:"Tables"`
}

func formatJSON(sql string, db string, suggest map[string]Rule) string {
	var id, fingerprint, result string

	fingerprint = query.Fingerprint(sql)
	id = query.Id(fingerprint)

	// Score
	score := 100
	for item := range suggest {
		l, err := strconv.Atoi(strings.TrimLeft(suggest[item].Severity, "L"))
		if err != nil {
			common.Log.Error("formatJSON strconv.Atoi error: %s, item: %s, serverity: %s", err.Error(), item, suggest[item].Severity)
		}
		score = score - l*5
		// ## MySQL execute failed
		if strings.HasPrefix(item, "ERR") && suggest[item].Content != "" {
			score = 0
		}
	}
	if score < 0 {
		score = 0
	}

	sug := JSONSuggest{
		ID:          id,
		Fingerprint: fingerprint,
		Sample:      sql,
		Tables:      ast.SchemaMetaInfo(sql, db),
		Score:       score,
	}

	// Explain info
	var sortItem []string
	for item := range suggest {
		if strings.HasPrefix(item, "EXP") {
			sortItem = append(sortItem, item)
		}
	}
	sort.Strings(sortItem)
	for _, i := range sortItem {
		sug.Explain = append(sug.Explain, suggest[i])
	}
	sortItem = make([]string, 0)

	// Index advisor
	for item := range suggest {
		if strings.HasPrefix(item, "IDX") {
			sortItem = append(sortItem, item)
		}
	}
	sort.Strings(sortItem)
	for _, i := range sortItem {
		sug.IndexRules = append(sug.IndexRules, suggest[i])
	}
	sortItem = make([]string, 0)

	// Heuristic rules
	for item := range suggest {
		if !strings.HasPrefix(item, "EXP") && !strings.HasPrefix(item, "IDX") {
			if strings.HasPrefix(item, "ERR") && suggest[item].Content == "" {
				continue
			}
			sortItem = append(sortItem, item)
		}
	}
	sort.Strings(sortItem)
	for _, i := range sortItem {
		sug.HeuristicRules = append(sug.HeuristicRules, suggest[i])
	}
	sortItem = make([]string, 0)

	js, err := json.MarshalIndent(sug, "", "  ")
	if err == nil {
		result = fmt.Sprint(string(js))
	} else {
		common.Log.Error("formatJSON json.Marshal Error: %v", err)
	}
	return result
}

// ListHeuristicRules 打印支持的启发式规则，对应命令行参数-list-heuristic-rules
func ListHeuristicRules(rules ...map[string]Rule) {
	switch common.Config.ReportType {
	case "json":
		js, err := json.MarshalIndent(rules, "", "  ")
		if err == nil {
			fmt.Println(string(js))
		}
	default:
		fmt.Print("# 启发式规则建议\n\n[toc]\n\n")
		for _, r := range rules {
			delete(r, "OK")
			for _, item := range common.SortedKey(r) {
				fmt.Print("## ", common.MarkdownEscape(r[item].Summary),
					"\n\n* **Item**:", r[item].Item,
					"\n* **Severity**:", r[item].Severity,
					"\n* **Content**:", common.MarkdownEscape(r[item].Content),
					"\n* **Case**:\n\n```sql\n", r[item].Case, "\n```\n")
			}
		}
	}
}

// ListTestSQLs 打印测试用的SQL，方便测试，对应命令行参数-list-test-sqls
func ListTestSQLs() {
	for _, sql := range common.TestSQLs {
		fmt.Println(sql)
	}
}
