<?php

class DbHandler {

    private $conn;

    function __construct() {
        require_once dirname(__FILE__) . '/DbConnect.php';
        // opening db connection
        $db = new DbConnect();
        $this->conn = $db->connect();
    }

    /* ------------- `users` table method ------------------ */

   
    public function createUser($firstName, $lastName, $password, $mobNum, $emailId, $dob,
            $country, $city, $bloodGroup, $status) {
        require_once 'PassHash.php';
        $response = array();
        $date=date("Y-m-d",strtotime($dob));
        // First check if user already existed in db
        if (!$this->isUserExists($emailId)) {
             // Generating password hash
            $password_hash = PassHash::hash($password);
            // Generating API key
            $api_key = $this->generateApiKey();

            // insert query
            $stmt = $this->conn->prepare("INSERT INTO registration(first_name, last_name, password_hash, mob_num, email_id, dob, country, city, blood_group, status, api_key) values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("sssssssssis", $firstName, $lastName, $password_hash, $mobNum, $emailId, $date, $country, $city, $bloodGroup, $status, $api_key);

            $result = $stmt->execute();

            $stmt->close();

            // Check for successful insertion
            if ($result) {
                // User successfully inserted
                return USER_CREATED_SUCCESSFULLY;
            } else {
                // Failed to create user
                return USER_CREATE_FAILED;
            }
        } else {
            // User with same email already existed in the db
            return USER_ALREADY_EXISTED;
        }

        return $response;
    }
    
     /**
     * Checking user login
     * @param String $email User login email id
     * @param String $password User login password
     * @return boolean User login status success/fail
     */
    public function checkLogin($emailId, $password) {
        // fetching user by email
        $stmt = $this->conn->prepare("SELECT password_hash FROM registration WHERE email_id = ?");

        $stmt->bind_param("s", $emailId);

        $stmt->execute();

        $stmt->bind_result($password_hash);

        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            // Found user with the email
            // Now verify the password

            $stmt->fetch();

            $stmt->close();

            if (PassHash::check_password($password_hash, $password)) {
                // User password is correct
                return TRUE;
            } else {
                // user password is incorrect
                return FALSE;
            }
        } else {
            $stmt->close();

            // user not existed with the email
            return FALSE;
        }
    }

  
    /**
     * Checking for duplicate user by email address
     * @param String $email email to check in db
     * @return boolean
     */
    private function isUserExists($emailId) {
        $stmt = $this->conn->prepare("SELECT reg_id from registration WHERE email_id = ?");
        $stmt->bind_param("s", $emailId);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }
    
   
    
    

    /**
     * Fetching user by email
     * @param String $email User email id
     */
   public function getUserByEmail($emailId) {
        $stmt = $this->conn->prepare("SELECT reg_id, first_name, last_name, password_hash, mob_num, email_id, dob, country, city, blood_group, status, api_key FROM registration WHERE email_id = ?");
        $stmt->bind_param("s", $emailId);
        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $stmt->bind_result($regId, $firstName, $lastName, $password, $mobNum, $emailId, $dob, $country, $city, $bloodGroup, $status, $apiKey);
            $stmt->fetch();
            $user = array();
            
            $user["regId"] = $regId;
            $user["firstName"] = $firstName;
            $user["lastName"] = $lastName;
            $user["password"] = $password;
            $user["mobNum"] = $mobNum;
            $user["emailId"] = $emailId;
            $user["dob"] = $dob;
            $user["country"] = $country;
            $user["city"] = $city;
            $user["bloodGroup"] = $bloodGroup;
            $user["status"] = $status;
            $user["apiKey"] = $apiKey;
            $stmt->close();
            return $user;
        } else {
            return NULL;
        }
    }
    

    /**
     * Fetching user api key
     * @param String $user_id user id primary key in user table
     */
    public function getApiKeyById($reg_id) {
        $stmt = $this->conn->prepare("SELECT api_key FROM registration WHERE reg_id = ?");
        $stmt->bind_param("i", $reg_id);
        if ($stmt->execute()) {
            // $api_key = $stmt->get_result()->fetch_assoc();
            // TODO
            $stmt->bind_result($api_key);
            $stmt->close();
            return $api_key;
        } else {
            return NULL;
        }
    }

    /**
     * Fetching user id by api key
     * @param String $api_key user api key
     */
    public function getUserId($api_key) {
        $stmt = $this->conn->prepare("SELECT reg_id FROM registration WHERE api_key = ?");
        $stmt->bind_param("s", $api_key);
        if ($stmt->execute()) {
            $stmt->bind_result($reg_id);
            $stmt->fetch();
            // TODO
            // $user_id = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $reg_id;
        } else {
            return NULL;
        }
    }

    /**
     * Validating user api key
     * If the api key is there in db, it is a valid key
     * @param String $api_key user api key
     * @return boolean
     */
    public function isValidApiKey($api_key) {
        $stmt = $this->conn->prepare("SELECT reg_id from registration WHERE api_key = ?");
        $stmt->bind_param("s", $api_key);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }

    /**
     * Generating random Unique MD5 String for user Api key
     */
    private function generateApiKey() {
        return md5(uniqid(rand(), true));
    }
    
    /**
     * Update user information
     * @param type $regId
     * @param type $firstName
     * @param type $lastName
     * @param type $mobNum
     * @param type $emailId
     * @param type $dob
     * @param type $country
     * @param type $city
     * @param type $bloodGroup
     * @return type
     */
    public function updateUser($regId, $firstName, $lastName, $mobNum, $emailId, $dob, $country, $city, $bloodGroup) {
        
        $stmt = $this->conn->prepare("UPDATE registration set first_name = ?, last_name = ?, mob_num = ?, email_id = ?, dob = ?, country = ?, city = ?, blood_group = ? WHERE reg_id = ?");
        $stmt->bind_param("ssssssssi", $firstName, $lastName, $mobNum, $emailId, $dob, $country, $city, $bloodGroup, $regId);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }
    
    /**
     * 
     * @param type $country
     * @param type $city
     * @param type $bloodGroup
     * @return type
     */
    public function getDonorsList($country, $city, $bloodGroup) {
       $stmt = $this->conn->prepare("SELECT first_name, last_name, mob_num, email_id, dob, country, city, blood_group FROM registration WHERE country = ? AND city = ? AND blood_group = ?");
       $stmt->bind_param("sss", $country, $city, $bloodGroup);
       $stmt->execute();
       $donors = $stmt->get_result();
       $stmt->close();
       return $donors;
    }
    
    /**
     * Adding events to db
     * @param type $eventName
     * @param type $eventDesc
     * @param type $eventVenue
     * @param type $contactNum
     * @param type $eventDate
     * @return boolean
     */
     public function insertEvent($eventName, $eventDesc, $eventVenue, $contactNum, $eventDate) {
        $date=date("Y-m-d",strtotime($eventDate));
        // insert query
        $stmt = $this->conn->prepare("INSERT INTO events(event_name, event_desc, venue, contact_num, event_date) values(?, ?, ?, ?, ?)");
        $stmt->bind_param("sssis", $eventName, $eventDesc, $eventVenue, $contactNum, $date);

        $result = $stmt->execute();

        $stmt->close();

        // Check for successful insertion
        if ($result) {
            // User successfully inserted
            return TRUE;
        } else {
            // Failed to create user
            return FALSE;
        }
    }
    
   /**
    * 
    * @return type
    */
    
    public function getEventList() {
       $stmt = $this->conn->prepare("SELECT * FROM events WHERE event_date >= CURDATE()");
       //$stmt->bind_param("s", $country, $city, $bloodGroup);
       $stmt->execute();
       $events = $stmt->get_result();
       $stmt->close();
       return $events;
       
    }
    
    /**
     * checking whether alreday joined group
     * @param type $groupId
     * @param type $regId
     * @return type
     */
    private function isJoined($groupId,$regId){
        $stmt = $this->conn->prepare("SELECT * from members WHERE fk_group_id = ? AND fk_reg_id = ?");
        $stmt->bind_param("ii", $groupId,$regId);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }
    
    /**
     * Join to new group
     * @param type $groupId
     * @param type $regId
     * @return string|array
     */
    public function createGroupMembers($groupId, $regId) {
        $response = array();
        
        if (!$this->isJoined($groupId, $regId)) {
            
            $stmt = $this->conn->prepare("INSERT INTO members(fk_group_id, fk_reg_id) VALUES(?, ?)");
            $stmt->bind_param("ii", $groupId, $regId);
            $result = $stmt->execute();
            $stmt->close();

            if ($result) {
                return JOINED_SUCCESSFULLY;
            } else {
                return UNABLE_TO_JOIN;
            }
        }else {
            
            return ALREADY_JOINED;
        }
        
        return $response;
    }
        
     /**
     * Checking duplicated group
     * @param type $groupName
     * @return type
     */
    private function isGroupExists($groupName) {
        $stmt = $this->conn->prepare("SELECT group_id from groups WHERE group_name = ?");
        $stmt->bind_param("s", $groupName);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }
    
   /**
    * Creating new Group
    * @param type $groupName
    * @param type $regId
    * @return string|array
    */
    
    public function createGroup($groupName, $regId) {
        $response = array();
        if (!$this->isGroupExists($groupName)) {
            
            $stmt = $this->conn->prepare("INSERT INTO groups(group_name, group_admin) VALUES(?, ?)");
            $stmt->bind_param("si", $groupName, $regId);
            $result = $stmt->execute();
            $stmt->close();

            if ($result) {
                // task row created
                // now assign the task to user
                $new_group_id = $this->conn->insert_id;
                $res = $this->createMember($new_group_id, $regId);
                if ($res) {
                    // task created successfully
                    return GROUP_CREATED_SUCCESSFULLY;
                } else {
                    // task failed to create
                    return GROUP_CREATE_FAILED;
                }
            } else {
                // task failed to create
                return GROUP_CREATE_FAILED;
            }
        }else {
            // User with same email already existed in the db
            return GROUP_ALREADY_EXISTED;
        }
        
        return $response;
    }
    
    /**
     * Add Group Admin
     * @param type $groupId
     * @param type $regId
     * @return boolean
     */
    
     public function createMember($groupId, $regId) {
        $stmt = $this->conn->prepare("INSERT INTO members(fk_group_id, fk_reg_id) values(?, ?)");
        $stmt->bind_param("ii", $groupId, $regId);
        $result = $stmt->execute();

        if (false === $result) {
            die('execute() failed: ' . htmlspecialchars($stmt->error));
        }
        
        $stmt->close();
        
        if($result){
            return TRUE;
        }else{
            return FALSE;
        }
        
    }
    
    /**
     * 
     * @param type $regId
     * @return type
     */
     public function getGenericGroupsList($regId) {
       $stmt = $this->conn->prepare("select group_id,group_name from groups g,members m 
                                    where g.group_id = m.fk_group_id
                                    and m.fk_reg_id <> ? 
                                    group by g.group_name
                                    order by g.group_id;");
       $stmt->bind_param("i", $regId);
       $stmt->execute();
       $groups = $stmt->get_result();
       $stmt->close();
       return $groups;
       
    }
    
    /**
     * 
     * @param type $regId
     * @return type
     */
     public function getSpecificGroupsList($regId) {
       $stmt = $this->conn->prepare("select group_id,group_name from groups g,members m 
                                    where g.group_id = m.fk_group_id
                                    and m.fk_reg_id = ? 
                                    group by g.group_name
                                    order by g.group_id");
       $stmt->bind_param("i", $regId);
       $stmt->execute();
       $groups = $stmt->get_result();
       $stmt->close();
       return $groups;
       
    }
    
    /**
     * Count the num of donors in a group
     * @param type $groupId
     * @return type
     */
    public function getCountGroupDonorEmergency($groupId){
        
       $stmt = $this->conn->prepare("select reg_id, first_name, last_name, mob_num, email_id, dob, country, city, blood_group
                                    from registration r,members m     
                                    where r.reg_id = m.fk_reg_id
                                    and m.fk_group_id = ?
                                    group by r.reg_id
                                    order by r.reg_id");
       $stmt->bind_param("i", $groupId);
       $stmt->execute();
       $stmt->store_result();
       $num_rows = $stmt->num_rows;
       $stmt->close();
       return $num_rows;
    }
    
    /**
     * Pagination for donors from a each group
     * @param type $groupId
     * @param type $currentpage
     * @return type
     */
    
    public function getGroupDonorPagination($groupId, $currentpage,$totalpages) {
        
        // number of rows to show per page
        $rowsperpage = 10;

        // get the current page or set a default
        /*if (isset($_GET[$page]) && is_numeric($_GET[$page])) {
           // cast var as int
           $currentpage = (int) $_GET[$page];
        } else {
           // default page num
           $currentpage = 1;
        } */// end if

        // if current page is greater than total pages...
        if ($currentpage > $totalpages) {
           // set current page to last page
           $currentpage = $totalpages;
        } // end if
        // if current page is less than first page...
        if ($currentpage < 1) {
           // set current page to first page
           $currentpage = 1;
        } // end if

        // the offset of the list, based on current page 
        $offset = ($currentpage - 1) * $rowsperpage;
        
        $stmt = $this->conn->prepare("select reg_id, first_name, last_name, mob_num, email_id, dob, country, city, blood_group
                                    from registration r,members m     
                                    where r.reg_id = m.fk_reg_id
                                    and m.fk_group_id = ?
                                    group by r.reg_id
                                    order by r.reg_id
                                    LIMIT ?, ?");
        $stmt->bind_param("iii", $groupId, $offset, $rowsperpage);
        $stmt->execute();
        $donors = $stmt->get_result();
        $stmt->close();
        return $donors;
       
    }
    
    /**
     * 
     * @param type $groupId
     * @return type
     */
    
    public function getDonorsListByGroup($groupId) {
       $stmt = $this->conn->prepare("select reg_id, first_name, last_name, mob_num, email_id, dob, country, city, blood_group
                                    from registration r,members m     
                                    where r.reg_id = m.fk_reg_id
                                    and m.fk_group_id = ?
                                    group by r.reg_id
                                    order by r.reg_id");
       $stmt->bind_param("i", $groupId);
       $stmt->execute();
       $donors = $stmt->get_result();
       $stmt->close();
       return $donors;
       
    }
    
    /**
     * Add bloodgroup need
     * @param type $bloodGroup
     * @param type $place
     * @param type $contactNum
     * @param type $tillDate
     * @return boolean
     */
    
    public function createBloodRequirement($bloodGroup, $place, $contactNum, $tillDate) {
        $date=date("Y-m-d",strtotime($tillDate));
        // insert query
        $stmt = $this->conn->prepare("INSERT INTO emergency(blood_group, place, contact_num, till_date) values(?, ?, ?, ?)");
        $stmt->bind_param("ssss", $bloodGroup, $place, $contactNum, $date);

        $result = $stmt->execute();

        $stmt->close();

        // Check for successful insertion
        if ($result) {
            // User successfully inserted
            return TRUE;
        } else {
            // Failed to create user
            return FALSE;
        }
    }
    
    /**
     * 
     * @return type
     */
     public function getBloodRequirementList() {
       $stmt = $this->conn->prepare("SELECT * FROM emergency WHERE till_date >= CURDATE()");
       //$stmt->bind_param("s", $country, $city, $bloodGroup);
       $stmt->execute();
       $needs = $stmt->get_result();
       $stmt->close();
       return $needs;
       
    }
    
    /**
     * Get num of blood need
     * @return num of rows
     */
    
    public function getCountEmergency(){
        
       $stmt = $this->conn->prepare("SELECT * from emergency WHERE till_date >= CURDATE() ORDER BY till_date");
       $stmt->execute();
       $stmt->store_result();
       $num_rows = $stmt->num_rows;
       $stmt->close();
       return $num_rows;
    }
    
    /**
     * Pagination blood need
     * @param type $currentpage
     * @return needs
     */

    public function getNeedBloodPagination($currentpage, $totalpages) {
        
        // number of rows to show per page
        $rowsperpage = 10;
        
        // find out total pages
        //$totalpages = ceil($numrows / $rowsperpage);

        // get the current page or set a default
        /*if (isset($_GET[$page]) && is_numeric($_GET[$page])) {
           // cast var as int
           $currentpage = (int) $_GET[$page];
        } else {
           // default page num
           $currentpage = 1;
        } */// end if

        // if current page is greater than total pages...
        if ($currentpage > $totalpages) {
           // set current page to last page
           $currentpage = $totalpages;
        } // end if
        // if current page is less than first page...
        if ($currentpage < 1) {
           // set current page to first page
           $currentpage = 1;
        } // end if

        // the offset of the list, based on current page 
        $offset = ($currentpage - 1) * $rowsperpage;
       
       $stmt = $this->conn->prepare("SELECT * FROM emergency WHERE till_date >= CURDATE() ORDER BY till_date LIMIT ?, ?");
       $stmt->bind_param("ii", $offset, $rowsperpage);
       $stmt->execute();
       $needs = $stmt->get_result();
       $stmt->close();
       return $needs;
       
    }
    
    /**
     * get count of events
     * @return type
     */
    
    public function getCountEvents(){
        
       $stmt = $this->conn->prepare("SELECT * from events WHERE event_date >= CURDATE() ORDER BY event_date");
       $stmt->execute();
       $stmt->store_result();
       $num_rows = $stmt->num_rows;
       $stmt->close();
       return $num_rows;
    }
    
    /**
     * Pagination events
     * @param type $currentpage
     * @return type
     */
    public function getEventPagination($currentpage,$totalpages) {
        
        
        //$numrows = $this->getCountEvents();
        
        // number of rows to show per page
        $rowsperpage = 10;
        
        // find out total pages
       // $totalpages = ceil($numrows / $rowsperpage);

        // get the current page or set a default
        /*if (isset($_GET[$page]) && is_numeric($_GET[$page])) {
           // cast var as int
           $currentpage = (int) $_GET[$page];
        } else {
           // default page num
           $currentpage = 1;
        } */// end if

        // if current page is greater than total pages...
        if ($currentpage > $totalpages) {
           // set current page to last page
           $currentpage = $totalpages;
        } // end if
        // if current page is less than first page...
        if ($currentpage < 1) {
           // set current page to first page
           $currentpage = 1;
        } // end if

        // the offset of the list, based on current page 
        $offset = ($currentpage - 1) * $rowsperpage;
        
        $stmt = $this->conn->prepare("SELECT * FROM events WHERE event_date >= CURDATE() ORDER BY event_date LIMIT ?, ?");
        $stmt->bind_param("ii", $offset, $rowsperpage);
        $stmt->execute();
        $events = $stmt->get_result();
        $stmt->close();
        return $events;
       
    }
    
    /**
     * get Num of donors
     * @return type
     */
    public function getCountSearchDonor($country, $city, $bloodGroup){
        
       $stmt = $this->conn->prepare("SELECT first_name, last_name, mob_num, email_id, dob, country, city, blood_group FROM registration WHERE country = ? AND city = ? AND blood_group = ? ORDER BY first_name");
       $stmt->bind_param("sss", $country, $city, $bloodGroup);
       $stmt->execute();
       $stmt->store_result();
       $num_rows = $stmt->num_rows;
       $stmt->close();
       return $num_rows;
    }
    
    public function getSearchDonorPagination($country, $city, $bloodGroup,$currentpage,$totalpages) {
        
        
        //$numrows = $this->getCountSearchDonor($country, $city, $bloodGroup);
        
        // number of rows to show per page
        $rowsperpage = 10;
        
        // find out total pages
        //$totalpages = ceil($numrows / $rowsperpage);

        // get the current page or set a default
        /*if (isset($_GET[$page]) && is_numeric($_GET[$page])) {
           // cast var as int
           $currentpage = (int) $_GET[$page];
        } else {
           // default page num
           $currentpage = 1;
        } */// end if

        // if current page is greater than total pages...
        if ($currentpage > $totalpages) {
           // set current page to last page
           $currentpage = $totalpages;
        } // end if
        // if current page is less than first page...
        if ($currentpage < 1) {
           // set current page to first page
           $currentpage = 1;
        } // end if

        // the offset of the list, based on current page 
        $offset = ($currentpage - 1) * $rowsperpage;
        
        $stmt = $this->conn->prepare("SELECT first_name, last_name, mob_num, email_id, dob, country, city, blood_group FROM registration WHERE country = ? AND city = ? AND blood_group = ? ORDER BY first_name LIMIT ?, ?");
        $stmt->bind_param("sssii", $country, $city, $bloodGroup,$offset, $rowsperpage);
        $stmt->execute();
        $donors = $stmt->get_result();
        $stmt->close();
        return $donors;
       
    }
    
    /**
     * Count num of generic group
     * @param type $regId
     * @return type
     */
    public function getCountGenericGroup($regId){
        $stmt = $this->conn->prepare("select group_id,group_name from groups g,members m 
                                    where g.group_id = m.fk_group_id
                                    and m.fk_reg_id <> ? 
                                    group by g.group_name
                                    order by g.group_name;");
        $stmt->bind_param("i", $regId);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows;
    }
    
    /**
     * Pagination generic group
     * @param type $regId
     * @param type $currentpage
     * @return type
     */
    public function getGenericGroupPagination($regId,$currentpage,$totalpages) {
        
        
        //$numrows = $this->getCountGenericGroup($regId);
        
        // number of rows to show per page
        $rowsperpage = 10;
        
        // find out total pages
        //$totalpages = ceil($numrows / $rowsperpage);

        // get the current page or set a default
        /*if (isset($_GET[$page]) && is_numeric($_GET[$page])) {
           // cast var as int
           $currentpage = (int) $_GET[$page];
        } else {
           // default page num
           $currentpage = 1;
        } */// end if

        // if current page is greater than total pages...
        if ($currentpage > $totalpages) {
           // set current page to last page
           $currentpage = $totalpages;
        } // end if
        // if current page is less than first page...
        if ($currentpage < 1) {
           // set current page to first page
           $currentpage = 1;
        } // end if

        // the offset of the list, based on current page 
        $offset = ($currentpage - 1) * $rowsperpage;
        
        $stmt = $this->conn->prepare("select group_id,group_name from groups g,members m 
                                    where g.group_id = m.fk_group_id
                                    and m.fk_reg_id <> ? 
                                    group by g.group_name
                                    order by g.group_name LIMIT ?, ?;");
        $stmt->bind_param("iii", $regId, $offset, $rowsperpage);
        $stmt->execute();
        $groups = $stmt->get_result();
        $stmt->close();
        return $groups;
       
    }
    
    /**
     * COunt num of specific group
     * @param type $regId
     * @return type
     */
    public function getCountSpecificGroup($regId){
        $stmt = $this->conn->prepare("select group_id,group_name from groups g,members m 
                                    where g.group_id = m.fk_group_id
                                    and m.fk_reg_id = ? 
                                    group by g.group_name
                                    order by g.group_name;");
        $stmt->bind_param("i", $regId);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows;
    }
    
    public function getSpecificGroupPagination($regId,$currentpage,$totalpages) {
        
        
        
        
        // number of rows to show per page
        $rowsperpage = 10;

        // get the current page or set a default
        /*if (isset($_GET[$page]) && is_numeric($_GET[$page])) {
           // cast var as int
           $currentpage = (int) $_GET[$page];
        } else {
           // default page num
           $currentpage = 1;
        } */// end if

        // if current page is greater than total pages...
        if ($currentpage > $totalpages) {
           // set current page to last page
           $currentpage = $totalpages;
        } // end if
        // if current page is less than first page...
        if ($currentpage < 1) {
           // set current page to first page
           $currentpage = 1;
        } // end if

        // the offset of the list, based on current page 
        $offset = ($currentpage - 1) * $rowsperpage;
        
        $stmt = $this->conn->prepare("select group_id,group_name from groups g,members m 
                                    where g.group_id = m.fk_group_id
                                    and m.fk_reg_id = ? 
                                    group by g.group_name
                                    order by g.group_name LIMIT ?, ?;");
        $stmt->bind_param("iii", $regId, $offset, $rowsperpage);
        $stmt->execute();
        $groups = $stmt->get_result();
        $stmt->close();
        return $groups;
       
    }

    /**
     * Deleting a task
     * @param String $task_id id of the task to delete
     */
    public function deleteTask($user_id, $task_id) {
        $stmt = $this->conn->prepare("DELETE t FROM tasks t, user_tasks ut WHERE t.id = ? AND ut.task_id = t.id AND ut.user_id = ?");
        $stmt->bind_param("ii", $task_id, $user_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }


}

?>
