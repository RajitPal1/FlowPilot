const mongoose = require("mongoose");
const config = require("./config");

async function connectDB(){
    try{
        await mongoose.connect(config.MONGO_URI);
        console.log("Connected to Database");
    }
    catch(err){
        console.log("Database not connected due to ", err);
    }
}

module.exports = connectDB;