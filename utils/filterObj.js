const filterObj = (obj, ...allowedFields) => {
     const newObj = {};
     Object.keys(obj).forEach(() => {
        if(allowedFields.includes(el)) newObj[el] = obj[el]
     })
     return newObj
}

module.exports = filterObj