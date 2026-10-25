const userModel = require("../models/user.model");
const userData = require("../data/userData.json");

async function verifyUser(req,res){

    const {id} = req.body;

    const isUserExists = userData.find({id:id});

    if(!isUserExists){
        return res.status(401).json({
            message:"User not found"
        })
    }

    res.status(200).json({
        message:"User found successfully"
    })

}