/*
 * Class used for user input attacks.
 */
package co.za.zwideheights.websec;

import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;

import java.util.ArrayList;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import co.za.zwideheights.websec.validate.PreventAttack;

public class WebSecTest {
	
	private String xss = "http://testsite.test/<script>alert(\"TEST\");</script>";
	private String sql = "SELECT * FROM users";
	private List<String> sqlDDLs ;
	private String testName;
	
    @BeforeClass
    public static void initWebSecTest() {

    }
 
    @Before
    public void beforeEachTest() {
    	System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++BEGIN+++++++++++++++++++++++++++++++++++++++++++++++++++++");
    }

    @After
    public void afterEachTest() {
    	System.out.println("------------------------------------------------DONE testing "+testName+"----------------------------------------------------");
    }

    @Test
    public void testCrossSiteScripting() {
    	testName = " Cross Site Scripting";
    	String result = PreventAttack.PreventCrossSiteScripting(xss);
    	assertThat(xss, not(result));
    }
    
    @Test
    public void testDropDDL() {
    	
    	sqlDDLs = new ArrayList<String>();
    	sqlDDLs.add("DROP INDEX index_name ON table_name");
    	sqlDDLs.add("DROP INDEX table_name.index_name");
    	sqlDDLs.add("DROP INDEX index_name");
    	sqlDDLs.add("ALTER TABLE table_name DROP INDEX index_name");
    	sqlDDLs.add("DROP TABLE table_name");
    	sqlDDLs.add("DROP DATABASE database_name");
    	sqlDDLs.add("TRUNCATE TABLE table_name");
    	
    	testName = " Drop DDL";
    	
    	for( String code : sqlDDLs ){
        	String result = PreventAttack.PreventSQLInjection(code);
        	assertThat(code, not(result));
    	}

    }
    
    @Test
    public void testSQLInjection() {
    	testName = " SQL Injection.";
    	String result = PreventAttack.PreventSQLInjection(sql);
    	assertThat(sql, not(result));
    }

}