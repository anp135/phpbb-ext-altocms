<?php
/**
 * Created by PhpStorm.
 * User: anp135
 * Date: 06.09.16
 * Time: 9:07
 */

namespace anp135\altocms;

class auth extends \phpbb\auth\auth {
    function login($username, $password, $autologin = false, $viewonline = 1, $admin = 0)
    {
        global $db, $user, $phpbb_root_path, $phpEx, $phpbb_container;
        global $phpbb_dispatcher;

        $provider_collection = $phpbb_container->get('auth.provider_collection');

        $provider = $provider_collection->get_provider();
        if ($provider)
        {
            $login = $provider->login($username, $password);

            // If the auth module wants us to create an empty profile do so and then treat the status as LOGIN_SUCCESS
            if ($login['status'] == LOGIN_SUCCESS_CREATE_PROFILE)
            {
                // we are going to use the user_add function so include functions_user.php if it wasn't defined yet
                if (!function_exists('user_add'))
                {
                    include($phpbb_root_path . 'includes/functions_user.' . $phpEx);
                }

                user_add($login['user_row'], (isset($login['cp_data'])) ? $login['cp_data'] : false);

                $sql = 'SELECT user_id, username, user_password, user_passchg, user_email, user_type
					FROM ' . USERS_TABLE . "
					WHERE username_clean = '" . $db->sql_escape(utf8_clean_string($username)) . "'";
                $result = $db->sql_query($sql);
                $row = $db->sql_fetchrow($result);
                $db->sql_freeresult($result);

                if (!$row)
                {
                    return array(
                        'status'		=> LOGIN_ERROR_EXTERNAL_AUTH,
                        'error_msg'		=> 'AUTH_NO_PROFILE_CREATED',
                        'user_row'		=> array('user_id' => ANONYMOUS),
                    );
                }

                $login = array(
                    'status'	=> LOGIN_SUCCESS,
                    'error_msg'	=> false,
                    'user_row'	=> $row,
                );
            }

            // If the auth provider wants us to link an empty account do so and redirect
            if ($login['status'] == LOGIN_SUCCESS_LINK_PROFILE)
            {
                // If this status exists a fourth field is in the $login array called 'redirect_data'
                // This data is passed along as GET data to the next page allow the account to be linked

                $params = array('mode' => 'login_link');
                $url = append_sid($phpbb_root_path . 'ucp.' . $phpEx, array_merge($params, $login['redirect_data']));

                redirect($url);
            }

            /**
             * Event is triggered after checking for valid username and password, and before the actual session creation.
             *
             * @event core.auth_login_session_create_before
             * @var	array	login				Variable containing login array
             * @var	bool	admin				Boolean variable whether user is logging into the ACP
             * @var	string	username			Username of user to log in
             * @var	bool	autologin			Boolean variable signaling whether login is triggered via auto login
             * @since 3.1.7-RC1
             */
            $vars = array(
                'login',
                'admin',
                'username',
                'autologin',
            );
            extract($phpbb_dispatcher->trigger_event('core.auth_login_session_create_before', compact($vars)));

            // If login succeeded, we will log the user in... else we pass the login array through...
            if ($login['status'] == LOGIN_SUCCESS)
            {
                $old_session_id = $user->session_id;

                if ($admin)
                {
                    global $SID, $_SID;

                    $cookie_expire = time() - 31536000;
                    $user->set_cookie('u', '', $cookie_expire);
                    //135
                    //$user->set_cookie('sid', '', $cookie_expire);
                    unset($cookie_expire);

                    //135
                    //$SID = '?sid=';
                    //$user->session_id = $_SID = '';
                    $user->session_id = session_id();
                }

                $result = $user->session_create($login['user_row']['user_id'], $admin, $autologin, $viewonline);

                // Successful session creation
                if ($result === true)
                {
                    // If admin re-authentication we remove the old session entry because a new one has been created...
                    if ($admin)
                    {
                        // the login array is used because the user ids do not differ for re-authentication
                        //135 Must update session not delete because right php session mechanism used.
                        //$sql = 'DELETE FROM ' . SESSIONS_TABLE . "
						//	WHERE session_id = '" . $db->sql_escape($old_session_id) . "'
						//	AND session_user_id = {$login['user_row']['user_id']}";
                        $sql = 'UPDATE ' . SESSIONS_TABLE . " SET session_admin = " . $admin ."
						WHERE session_id = '" . $db->sql_escape($user->session_id) . "'
						AND session_user_id = {$login['user_row']['user_id']}";
                        $db->sql_query($sql);
                    }

                    return array(
                        'status'		=> LOGIN_SUCCESS,
                        'error_msg'		=> false,
                        'user_row'		=> $login['user_row'],
                    );
                }

                return array(
                    'status'		=> LOGIN_BREAK,
                    'error_msg'		=> $result,
                    'user_row'		=> $login['user_row'],
                );
            }

            return $login;
        }

        trigger_error('Authentication method not found', E_USER_ERROR);
    }
}
