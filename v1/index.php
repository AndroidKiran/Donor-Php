<?php

require_once '../include/DbHandler.php';
require_once '../include/PassHash.php';
require '.././libs/Slim/Slim.php';

\Slim\Slim::registerAutoloader();

$app = new \Slim\Slim();

// User id from db - Global Variable
$user_id = NULL;

/**
 * Adding Middle Layer to authenticate every request
 * Checking if the request has valid api key in the 'Authorization' header
 */
function authenticate(\Slim\Route $route) {
    // Getting request headers
    $headers = apache_request_headers();
    $response = array();
    $app = \Slim\Slim::getInstance();

    // Verifying Authorization Header
    if (isset($headers['Authorization'])) {
        $db = new DbHandler();

        // get the api key
        $api_key = $headers['Authorization'];
        // validating api key
        if (!$db->isValidApiKey($api_key)) {
            // api key is not present in users table
            $response["error"] = true;
            $response["message"] = "Access Denied. Invalid Api key";
            echoRespnse(401, $response);
            $app->stop();
        } else {
            global $user_id;
            // get user primary key id
            $user_id = $db->getUserId($api_key);
        }
    } else {
        // api key is missing in header
        $response["error"] = true;
        $response["message"] = "Api key is misssing";
        echoRespnse(400, $response);
        $app->stop();
    }
}


/**
 * ----------- METHODS WITHOUT AUTHENTICATION ---------------------------------
 */
/**
 * User Registration
 * url - /register
 * method - POST
 * params - firstName', 'lastName', 'password', 'mobNum', 'emailId', 'dob', 'country', 'city', 'bloodGroup', 'status'
 */
$app->post('/register', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('firstName', 'lastName', 'password', 'mobNum', 'emailId', 'dob', 'country', 'city', 'bloodGroup', 'status'));

            $response = array();

            // reading post params
            $firstName = $app->request->post('firstName');
            $lastName = $app->request->post('lastName');
            $password = $app->request->post('password');
            $mobNum = $app->request->post('mobNum');
            $emailId = $app->request->post('emailId');
            $dob = $app->request->post('dob');
            $country = $app->request->post('country');
            $city = $app->request->post('city');
            $bloodGroup = $app->request->post('bloodGroup');
            $status = $app->request->post('status');
            
            // validating email address
            validateEmail($emailId);

            $db = new DbHandler();
            $res = $db->createUser($firstName, $lastName, $password, $mobNum, $emailId, $dob, $country, $city, $bloodGroup, $status);

            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });

/**
 * User Login
 * url - /login
 * method - POST
 * params - email, password
 */
$app->post('/login', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('emailId', 'password'));

            // reading post params
            $emailId = $app->request()->post('emailId');
            $password = $app->request()->post('password');
            $response = array();

            $db = new DbHandler();
            // check for correct email and password
            if ($db->checkLogin($emailId, $password)) {
                // get the user by email
                $user = $db->getUserByEmail($emailId);

                if ($user != NULL) {
                    $response["error"] = false;
                    $response["users"] = $user;
                  
                } else {
                    // unknown error occurred
                    $response["error"] = true;
                    $response["message"] = "An error occurred. Please try again";
                }
            } else {
                // user credentials are wrong
                $response["error"] = true;
                $response["message"] = 'Login failed. Incorrect credentials';
            }

            echoRespnse(200, $response);
        });



/*
 * ------------------------ METHODS WITH AUTHENTICATION ------------------------
 */
        
        
/*
   User Update
 * url - /user/:id
 * method - put
 * params - 'firstName', 'lastName', 'mobNum', 'emailId', 'dob', 'country', 'city', 'bloodGroup'
 */
$app->put('/user/id=:regId', 'authenticate', function($regId) use($app) {
            // check for required params
            verifyRequiredParams(array('firstName', 'lastName', 'mobNum', 'emailId', 'dob', 'country', 'city', 'bloodGroup'));

            // reading post params
            $firstName = $app->request->post('firstName');
            $lastName = $app->request->post('lastName');
            $mobNum = $app->request->post('mobNum');
            $emailId = $app->request->post('emailId');
            $dob = $app->request->post('dob');
            $country = $app->request->post('country');
            $city = $app->request->post('city');
            $bloodGroup = $app->request->post('bloodGroup');
            
             // validating email address
            validateEmail($emailId);

            $db = new DbHandler();
            $response = array();

            // updating task
            $result = $db->updateUser($regId, $firstName, $lastName, $mobNum, $emailId, $dob, $country, $city, $bloodGroup);
            if ($result) {
                // task updated successfully
                $response["error"] = false;
                $response["message"] = "User updated successfully";
            } else {
                // task failed to update
                $response["error"] = true;
                $response["message"] = "User failed to update. Please try again!";
            }
            echoRespnse(200, $response);
        });   

/**
 * Add events
 * method - POST
 * url - /events
 * params - 'eventName', 'eventDesc', 'eventVenue', 'contactNum', 'eventDate'
 */
        $app->post('/events', 'authenticate', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('eventName', 'eventDesc', 'eventVenue', 'eventContactNum', 'eventDate'));

            $response = array();

            // reading post params
            $eventName = $app->request->post('eventName');
            $eventDesc = $app->request->post('eventDesc');
            $eventVenue = $app->request->post('eventVenue');
            $contactNum = $app->request->post('eventContactNum');
            $eventDate = $app->request->post('eventDate');
            
            $db = new DbHandler();

            if ($db->insertEvent($eventName, $eventDesc, $eventVenue, $contactNum, $eventDate)) {
                $response["error"] = false;
                $response["message"] = "Event is Succesfully published";
            } else {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while publishing";
            } 
            // echo json response
            echoRespnse(201, $response);
        });
        
/**
 * Listing events 
 * method GET
 * url /events
 * Will return 404 if the task doesn't belongs to user
 */
        $app->get('/events', 'authenticate', function() {
           
            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getEventList();

            if ($result != NULL) {
                $response["error"] = false;
                $response["events"] = array();

                // looping through result and preparing donors array
                while ($event = $result->fetch_assoc()) {
                    $tmp = array();
                    $tmp["eventId"] = $event["event_id"];
                    $tmp["eventName"] = $event["event_name"];
                    $tmp["eventDesc"] = $event["event_desc"];
                    $tmp["eventVenue"] = $event["venue"];
                    $tmp["eventContactNum"] = $event["contact_num"];
                    $tmp["eventDate"] = $event["event_date"];
                   
                    array_push($response["events"], $tmp);
                }

                echoRespnse(200, $response);
                
            } else {
                $response["error"] = true;
                $response["message"] = "The requested resource doesn't exists";
                echoRespnse(404, $response);
            }
        });
        
        /**
         * GET Events
         */
        $app->get('/events/page=:currentpage', 'authenticate', function($currentpage) {
           
            $response = array();
            $db = new DbHandler();
            $numrows = $db->getCountEvents();
            $rowsperpage = 10;
            $totalpages = ceil($numrows / $rowsperpage);
            
            if ($numrows > 0){
                $result = $db->getEventPagination($currentpage, $totalpages);

                if ($result != NULL) {
                    $response["error"] = false;
                    $response["pages"] = $totalpages;
                    $response["events"] = array();
                    // looping through result and preparing donors array
                    while ($event = $result->fetch_assoc()) {
                        $tmp = array();
                        $tmp["eventId"] = $event["event_id"];
                        $tmp["eventName"] = $event["event_name"];
                        $tmp["eventDesc"] = $event["event_desc"];
                        $tmp["eventVenue"] = $event["venue"];
                        $tmp["eventContactNum"] = $event["contact_num"];
                        $tmp["eventDate"] = $event["event_date"];

                        array_push($response["events"], $tmp);
                    }

                    echoRespnse(200, $response);

                } else {
                    $response["error"] = true;
                    $response["message"] = "The requested resource doesn't exists";
                    echoRespnse(404, $response);
                }
            }else{
                $response["error"] = true;
                $response["message"] = "The requested data Absent";
                echoRespnse(201, $response);
            }
        });
        
/**
 * Listing donors 
 * method GET
 * url /donors/list/:country/:city/:bloodgroup
 * Will return 404 if the task doesn't belongs to user
 */
$app->get('/donorlist/:country/:city/:bloodGroup', 'authenticate', function($country, $city, $bloodGroup) {
           
            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getDonorsList($country,$city, $bloodGroup);

            if ($result != NULL) {
                $response["error"] = false;
                $response["donors"] = array();

                // looping through result and preparing donors array
                while ($donor = $result->fetch_assoc()) {
                    $tmp = array();
                   
                    $tmp["firstName"] = $donor["first_name"];
                    $tmp["lastName"] = $donor["last_name"];
                    $tmp["mobNum"] = $donor["mob_num"];
                    $tmp["emailId"] = $donor["email_id"];
                    $tmp["dob"] = $donor["dob"];
                    $tmp["country"] = $donor["country"];
                    $tmp["city"] = $donor["city"];
                    $tmp["bloodGroup"] = $donor["blood_group"];
                    
                    array_push($response["donors"], $tmp);
                }

                echoRespnse(200, $response);
                
            } else {
                $response["error"] = true;
                $response["message"] = "The requested resource doesn't exists";
                echoRespnse(404, $response);
            }
        });
        
        
        /**
         * Donor search
         */
        $app->get('/donorlist/country=:country/city=:city/bloodgroup=:bloodGroup/page=:currentpage', 'authenticate', function($country, $city, $bloodGroup,$currentpage) {
           
            $response = array();
            $db = new DbHandler();
            
            $numrows = $db->getCountSearchDonor($country, $city, $bloodGroup);
            $rowsperpage = 10;
            $totalpages = ceil($numrows / $rowsperpage);
            
            if ($numrows > 0 && $currentpage <= $totalpages ){
                $result = $db->getSearchDonorPagination($country, $city, $bloodGroup, $currentpage, $totalpages);
                
                if ($result != NULL) {
                    $response["error"] = false;
                    $response["pages"] = $totalpages;
                    $response["donors"] = array();

                    // looping through result and preparing donors array
                    while ($donor = $result->fetch_assoc()) {
                        $tmp = array();

                        $tmp["firstName"] = $donor["first_name"];
                        $tmp["lastName"] = $donor["last_name"];
                        $tmp["mobNum"] = $donor["mob_num"];
                        $tmp["emailId"] = $donor["email_id"];
                        $tmp["dob"] = $donor["dob"];
                        $tmp["country"] = $donor["country"];
                        $tmp["city"] = $donor["city"];
                        $tmp["bloodGroup"] = $donor["blood_group"];

                        array_push($response["donors"], $tmp);
                    }

                    echoRespnse(200, $response);

                } else {
                    $response["error"] = true;
                    $response["message"] = "The requested resource doesn't exists";
                    echoRespnse(404, $response);
                }
            }else{
                $response["error"] = true;
                $response["message"] = "The requested data not found";
                echoRespnse(201, $response);
            }

            // fetch task
            

            
        });
        

/**
 * Add groups 
 * method POST
 * url /groups
 * param - 'groupName', 'regId'
 * Will return 404 if the task doesn't belongs to user
 */
        $app->post('/groups', 'authenticate', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('groupName', 'regId'));

            $response = array();
            $groupName = $app->request->post('groupName');
            $regId = $app->request->post('regId');

            $db = new DbHandler();

            // creating new task
            $res = $db->createGroup($groupName, $regId);

            if ($res == GROUP_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "Group is successfully created";
            } else if ($res == GROUP_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while creating group";
            } else if ($res == GROUP_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this group already existed";
            }
            // echo json response
            echoRespnse(201, $response);  
        });
        
/**
 * listing generic groups 
 * method GET
 * url /groups/generic/:regId
 * Will return 404 if the task doesn't belongs to user
 */
        
        $app->get('/groups/:category/:regId', 'authenticate', function($category,$regId) {
           
            $response = array();
            $db = new DbHandler();

            if ($category == 'generic'){
                $result = $db->getGenericGroupsList($regId);
            }else if($category == 'specific'){
                $result = $db->getSpecificGroupsList($regId);
            }
           // $result = $db->getGenericGroupsList($regId);

            if ($result != NULL) {
                $response["error"] = false;
                $response["groups"] = array();

                // looping through result and preparing donors array
                while ($group = $result->fetch_assoc()) {
                    $tmp = array();
                    $tmp["groupId"] = $group["group_id"];
                    $tmp["groupName"] = $group["group_name"];
                    
                    array_push($response["groups"], $tmp);
                }

                echoRespnse(200, $response);
                
            } else {
                $response["error"] = true;
                $response["message"] = "The requested resource doesn't exists";
                echoRespnse(404, $response);
            }
        });
        
        
        /**
         * GET Groups
         */
        $app->get('/groups/category=:category/regid=:regId/page=:currentpage', 'authenticate', function($category, $regId, $currentpage) {
           
            $response = array();
            $db = new DbHandler();
            
            $rowsperpage = 10;
            
            if ($category == 'generic'){
                $numrows = $db->getCountGenericGroup($regId);
                $totalpages = ceil($numrows / $rowsperpage);
                if ($numrows > 0 && $currentpage <= $totalpages ){
                    $result = $db->getGenericGroupPagination($regId, $currentpage, $totalpages);
                    
                    if ($result != NULL) {
                        $response["error"] = false;
                        $response["pages"] = $totalpages;
                        $response["groups"] = array();
                        // looping through result and preparing donors array
                        while ($group = $result->fetch_assoc()) {
                            $tmp = array();
                            $tmp["groupId"] = $group["group_id"];
                            $tmp["groupName"] = $group["group_name"];

                            array_push($response["groups"], $tmp);
                        }

                        echoRespnse(200, $response);

                    } else {
                        $response["error"] = true;
                        $response["message"] = "The requested resource doesn't exists";
                        echoRespnse(404, $response);
                    }
                }
                else{
                    $response["error"] = true;
                    $response["message"] = "The requested Data not found";
                    echoRespnse(201, $response);
                }
            }else if($category == 'specific'){
                $numrows = $db->getCountSpecificGroup($regId);
                $totalpages = ceil($numrows / $rowsperpage);
                if ($numrows > 0 && $currentpage <= $totalpages ){
                    $result = $db->getSpecificGroupPagination($regId, $currentpage, $totalpages);
                    
                    if ($result != NULL) {
                        $response["error"] = false;
                        $response["pages"] = $totalpages;
                        $response["groups"] = array();
                        // looping through result and preparing donors array
                        while ($group = $result->fetch_assoc()) {
                            $tmp = array();
                            $tmp["groupId"] = $group["group_id"];
                            $tmp["groupName"] = $group["group_name"];

                            array_push($response["groups"], $tmp);
                        }

                        echoRespnse(200, $response);

                    } else {
                        $response["error"] = true;
                        $response["message"] = "The requested resource doesn't exists";
                        echoRespnse(404, $response);
                    }
                }
                else{
                    $response["error"] = true;
                    $response["message"] = "The requested Data not found";
                    echoRespnse(201, $response);
                }
            }
            
        });
        

/**
 * listing donors by group id 
 * method GET
 * url /donors/groups/:groupId
 * Will return 404 if the task doesn't belongs to user
 */
$app->get('/groups/:groupId', 'authenticate', function($groupId) {
           
            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getDonorsListByGroup($groupId);

            if ($result != NULL) {
                $response["error"] = false;
                $response["donors"] = array();

                // looping through result and preparing donors array
                while ($donor = $result->fetch_assoc()) {
                    $tmp = array();
                    $tmp["regId"] = $donor["reg_id"];
                    $tmp["firstName"] = $donor["first_name"];
                    $tmp["lastName"] = $donor["last_name"];
                    $tmp["mobNum"] = $donor["mob_num"];
                    $tmp["emailId"] = $donor["email_id"];
                    $tmp["dob"] = $donor["dob"];
                    $tmp["country"] = $donor["country"];
                    $tmp["city"] = $donor["city"];
                    $tmp["bloodGroup"] = $donor["blood_group"];
                   
                    array_push($response["donors"], $tmp);
                }

                echoRespnse(200, $response);
                
            } else {
                $response["error"] = true;
                $response["message"] = "The requested resource doesn't exists";
                echoRespnse(404, $response);
            }
        });
        
        /**
         * GET group Members
         */
        $app->get('/groups/donor/groupid=:groupId/page=:currentpage', 'authenticate', function($groupId,$currentpage) {
           
            $response = array();
            $db = new DbHandler();
            
            $numrows = $db->getCountGroupDonorEmergency($groupId);
            $rowsperpage = 10;
            $totalpages = ceil($numrows / $rowsperpage);
            
            if ($numrows > 0 && $currentpage <= $totalpages ){
                $result = $db->getGroupDonorPagination($groupId, $currentpage, $totalpages);
                
                if ($result != NULL) {
                    $response["error"] = false;
                    $response["pages"] = $totalpages;
                    $response["donors"] = array();
                    
                    // looping through result and preparing donors array
                    while ($donor = $result->fetch_assoc()) {
                        $tmp = array();
                        $tmp["regId"] = $donor["reg_id"];
                        $tmp["firstName"] = $donor["first_name"];
                        $tmp["lastName"] = $donor["last_name"];
                        $tmp["mobNum"] = $donor["mob_num"];
                        $tmp["emailId"] = $donor["email_id"];
                        $tmp["dob"] = $donor["dob"];
                        $tmp["country"] = $donor["country"];
                        $tmp["city"] = $donor["city"];
                        $tmp["bloodGroup"] = $donor["blood_group"];

                        array_push($response["donors"], $tmp);
                    }
                    echoRespnse(200, $response);
                } else {
                    $response["error"] = true;
                    $response["message"] = "The requested resource doesn't exists";
                    echoRespnse(404, $response);
                }
            }else{
                $response["error"] = true;
                $response["message"] = "The requested data not found";
                echoRespnse(201, $response);
            }
            
        });
        
/**
 * Adding members
 * method POST
 * url /members
 * params 'groupId', 'regId'
 * Will return 404 if the task doesn't belongs to user
 */
        $app->post('/join', 'authenticate', function() use ($app) {
    
            verifyRequiredParams(array('groupId', 'regId'));

            $response = array();
            $groupId = $app->request->post('groupId');
            $regId = $app->request->post('regId');

            $db = new DbHandler();

            // creating new task
            $res = $db->createGroupMembers($groupId, $regId);

            if ($res == JOINED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You Have Joined Group Successfully";
            } else if ($res == UNABLE_TO_JOIN) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while joining the group";
            } else if ($res == ALREADY_JOINED) {
                $response["error"] = true;
                $response["message"] = "Sorry, You are already member of the group";
            }
            // echo json response
            echoRespnse(201, $response);  
        });
        
/**
 * Adding Emergency
 * method POST
 * url /emergency
 * params 'bloodGroup', 'place', 'contactNum', 'tillDate'
 * Will return 404 if the task doesn't belongs to user
 */
        $app->post('/emergency', 'authenticate', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('bloodGroup', 'place', 'contactNum', 'tillDate'));

            $response = array();

            // reading post params
            $bloodGroup = $app->request->post('bloodGroup');
            $place = $app->request->post('place');
            $contactNum = $app->request->post('contactNum');
            $tillDate = $app->request->post('tillDate');
            
            
            $db = new DbHandler();

            if ($db->createBloodRequirement($bloodGroup, $place, $contactNum, $tillDate)) {
                $response["error"] = false;
                $response["message"] = "Blood requirement is Succesfully published";
            } else {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while publishing";
            } 
            // echo json response
            echoRespnse(201, $response);
        });
        
        
/**
 * Listing Blood requirement
 * method GET
 * url /emergency
 * Will return 404 if the task doesn't belongs to user
 */
        $app->get('/emergency', 'authenticate', function() {
           
            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getBloodRequirementList();

            if ($result != NULL) {
                $response["error"] = false;
                $response["needs"] = array();

                // looping through result and preparing donors array
                while ($need = $result->fetch_assoc()) {
                    $tmp = array();
                    $tmp["emergencyId"] = $need["emergency_id"];
                    $tmp["bloodGroup"] = $need["blood_group"];
                    $tmp["place"] = $need["place"];
                    $tmp["contactNum"] = $need["contact_num"];
                   
                    array_push($response["needs"], $tmp);
                }

                echoRespnse(200, $response);
                
            } else {
                $response["error"] = true;
                $response["message"] = "The requested resource doesn't exists";
                echoRespnse(404, $response);
            }
        });
        
        /**
         * GET Emergency Need
         */
        $app->get('/emergency/page=:currentpage', 'authenticate', function($currentpage) {
           
            $response = array();
            $db = new DbHandler();
            $numrows = $db->getCountEmergency();
            $rowsperpage = 10;
            $totalpages = ceil($numrows / $rowsperpage);
            
            if ($numrows > 0){
                $result = $db->getNeedBloodPagination($currentpage, $totalpages);
                
                // fetch task
                if ($result != NULL) {
                    $response["error"] = false;
                    $response["pages"] = $totalpages;
                    $response["needs"] = array();

                    // looping through result and preparing donors array
                    while ($need = $result->fetch_assoc()) {
                        $tmp = array();
                        $tmp["emergencyId"] = $need["emergency_id"];
                        $tmp["bloodGroup"] = $need["blood_group"];
                        $tmp["place"] = $need["place"];
                        $tmp["contactNum"] = $need["contact_num"];

                        array_push($response["needs"], $tmp);
                    }

                    echoRespnse(200, $response);

                } else {
                    $response["error"] = true;
                    $response["message"] = "The requested resource doesn't exists";
                    echoRespnse(404, $response);
                }
            }else{
               $response["error"] = true;
               $response["message"] = "The requested data not found";
               echoRespnse(201, $response);
            }
        });
/**
 * Deleting task. Users can delete only their tasks
 * method DELETE
 * url /tasks
 */
    $app->delete('/tasks/:id', 'authenticate', function($task_id) use($app) {
            global $user_id;

            $db = new DbHandler();
            $response = array();
            $result = $db->deleteTask($user_id, $task_id);
            if ($result) {
                // task deleted successfully
                $response["error"] = false;
                $response["message"] = "Task deleted succesfully";
            } else {
                // task failed to delete
                $response["error"] = true;
                $response["message"] = "Task failed to delete. Please try again!";
            }
            echoRespnse(200, $response);
        });

/**
 * Verifying required params posted or not
 */
function verifyRequiredParams($required_fields) {
    $error = false;
    $error_fields = "";
    $request_params = array();
    $request_params = $_REQUEST;
    // Handling PUT request params
    if ($_SERVER['REQUEST_METHOD'] == 'PUT') {
        $app = \Slim\Slim::getInstance();
        parse_str($app->request()->getBody(), $request_params);
    }
    foreach ($required_fields as $field) {
        if (!isset($request_params[$field]) || strlen(trim($request_params[$field])) <= 0) {
            $error = true;
            $error_fields .= $field . ', ';
        }
    }

    if ($error) {
        // Required field(s) are missing or empty
        // echo error json and stop the app
        $response = array();
        $app = \Slim\Slim::getInstance();
        $response["error"] = true;
        $response["message"] = 'Required field(s) ' . substr($error_fields, 0, -2) . ' is missing or empty';
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * Validating email address
 */
function validateEmail($email) {
    $app = \Slim\Slim::getInstance();
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $response["error"] = true;
        $response["message"] = 'Email address is not valid';
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * Echoing json response to client
 * @param String $status_code Http response code
 * @param Int $response Json response
 */
function echoRespnse($status_code, $response) {
    $app = \Slim\Slim::getInstance();
    // Http response code
    $app->status($status_code);

    // setting response content type to json
    $app->contentType('application/json');

    echo json_encode($response);
}

$app->run();
?>