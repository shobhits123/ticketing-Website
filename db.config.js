const dotenv =require("dotenv");
var mysql =require("mysql");
dotenv.config();

const config ={
  host: process.env.DB_CONNECT_HOST,
  user:process.env.DB_CONNECT_USER,
  password: process.env.DB_CONNECT_PASS,
  database:process.env.DB_CONNECT_DATABASE,
};
var con=mysql.createConnection(config);

con.connect(function(err){
  if (err) throw err;
  console.log("Database Connected Successful");

});
function funselect(sql){
  con.query(sql,(err,result)=>{
    if(err) throw err;
    return result;
  });
}
module.exports = con;