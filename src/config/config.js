require("dotenv").config();

if(!process.env.MONGO_URI){
    console.log("MONGO_URI is declared as a environmental variable");
}

const config = {
    MONGO_URI:process.env.MONGO_URI
}

module.exports = config;