import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.sql.DataSource;
import com.mysql.cj.jdbc.MysqlDataSource; // 注意导入的是 com.mysql.cj.jdbc.MysqlDataSource

public class DatabaseManager {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/test";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "511511";

    private static DataSource dataSource;

    static {
        // 初始化连接池
        dataSource = setupDataSource();
    }

    private static DataSource setupDataSource() {
        MysqlDataSource ds = new MysqlDataSource();
        ds.setURL(DB_URL);
        ds.setUser(DB_USER);
        ds.setPassword(DB_PASSWORD);
        return ds;
    }

    public static Connection getConnection() throws SQLException {
        return dataSource.getConnection();
    }

    public static void executeQuery(String mode,String cipher,String ffx,String sample,int flag) throws SQLException {
        Connection conn = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;
        String sql;
        if(flag==1){
            sql= "SELECT "+mode+",cast(fpe("+mode+",'"+mode+"','"+cipher+"','"+ffx+"','"+sample+"') as char) from test.student limit 10";
        }else{
            sql= "SELECT "+mode+",cast(fpe("+mode+",'"+mode+"','"+cipher+"','"+ffx+"') as char) from test.student limit 10";
        }
        System.out.println(sql);
        try {
            conn = getConnection();
            stmt = conn.prepareStatement(sql);
            // 设置查询参数
            rs = stmt.executeQuery();
            while (rs.next()) {
                String res=rs.getString(1);
                res = res +" "+rs.getString(2);
                System.out.println(res);
            }
        } catch (SQLException e) {
            // 处理异常
            e.printStackTrace();
            throw e;
        } finally {
            // 关闭资源
            if (stmt != null) {
                stmt.close();
            }
            if (conn != null) {
                conn.close();
            }
        }
    }

    public static void main(String[] args) {
        String mode="address";
        String cipher="aes";
        String ffx="ff1";
        String  sample="4414**********1234";
        // 在这里调用 executeQuery 方法执行查询
        try {
            executeQuery(mode,cipher,ffx,sample,0); 
        } catch (SQLException e) {
            e.printStackTrace();
        }
    
    }
}

