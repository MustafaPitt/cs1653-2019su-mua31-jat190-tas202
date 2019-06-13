
import javax.swing.DefaultListModel;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author JAT190
 */
public class GroupGUI extends javax.swing.JFrame {
    GroupClient gc;
    UserToken token;
    /**
     * Creates new form GroupGUI
     */
    public GroupGUI() {
        initComponents();
    }
    
    public GroupGUI(UserToken t) {
        this();
        token = t;
        gc = new GroupClient();
        gc.connect("localhost", 8000);
        
        updateTokenLabel();
        updateGroupList();
        updateUserList();
    }
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        dlgCreateGroup = new javax.swing.JDialog();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        txtCreateGroupName = new javax.swing.JTextField();
        btnCreateGroupCancel = new javax.swing.JButton();
        btnCreateGroupOK = new javax.swing.JButton();
        dlgCreateUser = new javax.swing.JDialog();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        txtCreateUserName = new javax.swing.JTextField();
        btnCreateUserCancel = new javax.swing.JButton();
        bntCreateUserOK = new javax.swing.JButton();
        dlgAddUserToGroup = new javax.swing.JDialog();
        jLabel5 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        jLabel7 = new javax.swing.JLabel();
        txtAddUserToGroupUser = new javax.swing.JTextField();
        txtAddUserToGroupGroup = new javax.swing.JTextField();
        btnAddUserToGroupCancel = new javax.swing.JButton();
        btnAddUserToGroupOK = new javax.swing.JButton();
        dlgRemoveUserFromGroup = new javax.swing.JDialog();
        jLabel8 = new javax.swing.JLabel();
        jLabel9 = new javax.swing.JLabel();
        jLabel10 = new javax.swing.JLabel();
        txtRemoveUserFromGroupUser = new javax.swing.JTextField();
        txtRemoveUserFromGroupGroup = new javax.swing.JTextField();
        btnRemoveUserFromGroupCancel = new javax.swing.JButton();
        btnRemoveUserFromGroupOK = new javax.swing.JButton();
        dlgDeleteUser = new javax.swing.JDialog();
        jLabel11 = new javax.swing.JLabel();
        jLabel12 = new javax.swing.JLabel();
        txtDeleteUserUser = new javax.swing.JTextField();
        btnDeleteUserCancel = new javax.swing.JButton();
        btnDeleteUserOK = new javax.swing.JButton();
        dlgDeleteGroup = new javax.swing.JDialog();
        jLabel13 = new javax.swing.JLabel();
        jLabel14 = new javax.swing.JLabel();
        txtDeleteGroupGroup = new javax.swing.JTextField();
        btnDeleteGroupCancel = new javax.swing.JButton();
        btnDeleteGroupOK = new javax.swing.JButton();
        btnCreateUser = new javax.swing.JButton();
        btnDeleteUser = new javax.swing.JButton();
        jSeparator1 = new javax.swing.JSeparator();
        btnCreateGroup = new javax.swing.JButton();
        btnDeleteGroup = new javax.swing.JButton();
        bntAddToGroup = new javax.swing.JButton();
        btnRemoveFromGroup = new javax.swing.JButton();
        lblTokenInfo = new javax.swing.JLabel();
        jPanel2 = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        groupList = new javax.swing.JList<>();
        jPanel3 = new javax.swing.JPanel();
        jScrollPane2 = new javax.swing.JScrollPane();
        userList = new javax.swing.JList<>();

        dlgCreateGroup.setTitle("Create Group...");
        dlgCreateGroup.setModal(true);

        jLabel1.setText("Please enter the group to create.");

        jLabel2.setText("Group name:");

        btnCreateGroupCancel.setText("Cancel");

        btnCreateGroupOK.setText("OK");

        javax.swing.GroupLayout dlgCreateGroupLayout = new javax.swing.GroupLayout(dlgCreateGroup.getContentPane());
        dlgCreateGroup.getContentPane().setLayout(dlgCreateGroupLayout);
        dlgCreateGroupLayout.setHorizontalGroup(
            dlgCreateGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(dlgCreateGroupLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(dlgCreateGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(dlgCreateGroupLayout.createSequentialGroup()
                        .addGap(10, 10, 10)
                        .addComponent(jLabel2)
                        .addGap(18, 18, 18)
                        .addComponent(txtCreateGroupName, javax.swing.GroupLayout.PREFERRED_SIZE, 189, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(jLabel1))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, dlgCreateGroupLayout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(btnCreateGroupOK, javax.swing.GroupLayout.PREFERRED_SIZE, 73, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(btnCreateGroupCancel, javax.swing.GroupLayout.PREFERRED_SIZE, 73, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        dlgCreateGroupLayout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {btnCreateGroupCancel, btnCreateGroupOK});

        dlgCreateGroupLayout.setVerticalGroup(
            dlgCreateGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(dlgCreateGroupLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(dlgCreateGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(txtCreateGroupName, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(dlgCreateGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnCreateGroupCancel)
                    .addComponent(btnCreateGroupOK))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        dlgCreateUser.setTitle("Create User...");
        dlgCreateUser.setModal(true);

        jLabel3.setText("Please enter the user to create.");

        jLabel4.setText("Username:");

        txtCreateUserName.setText("jTextField1");

        btnCreateUserCancel.setText("Cancel");

        bntCreateUserOK.setText("OK");

        javax.swing.GroupLayout dlgCreateUserLayout = new javax.swing.GroupLayout(dlgCreateUser.getContentPane());
        dlgCreateUser.getContentPane().setLayout(dlgCreateUserLayout);
        dlgCreateUserLayout.setHorizontalGroup(
            dlgCreateUserLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(dlgCreateUserLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(dlgCreateUserLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(dlgCreateUserLayout.createSequentialGroup()
                        .addGap(10, 10, 10)
                        .addComponent(jLabel4)
                        .addGap(18, 18, 18)
                        .addComponent(txtCreateUserName))
                    .addGroup(dlgCreateUserLayout.createSequentialGroup()
                        .addComponent(jLabel3)
                        .addGap(0, 124, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, dlgCreateUserLayout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addComponent(bntCreateUserOK, javax.swing.GroupLayout.PREFERRED_SIZE, 73, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnCreateUserCancel, javax.swing.GroupLayout.PREFERRED_SIZE, 73, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap())
        );
        dlgCreateUserLayout.setVerticalGroup(
            dlgCreateUserLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(dlgCreateUserLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(dlgCreateUserLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel4)
                    .addComponent(txtCreateUserName, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(dlgCreateUserLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnCreateUserCancel)
                    .addComponent(bntCreateUserOK))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        dlgAddUserToGroup.setTitle("Add User to Group...");
        dlgAddUserToGroup.setModal(true);

        jLabel5.setText("Please enter the user and group names.");

        jLabel6.setText("Username:");

        jLabel7.setText("Group name:");

        txtAddUserToGroupUser.setText("jTextField1");

        txtAddUserToGroupGroup.setText("jTextField2");

        btnAddUserToGroupCancel.setText("Cancel");

        btnAddUserToGroupOK.setText("OK");

        javax.swing.GroupLayout dlgAddUserToGroupLayout = new javax.swing.GroupLayout(dlgAddUserToGroup.getContentPane());
        dlgAddUserToGroup.getContentPane().setLayout(dlgAddUserToGroupLayout);
        dlgAddUserToGroupLayout.setHorizontalGroup(
            dlgAddUserToGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(dlgAddUserToGroupLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(dlgAddUserToGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(dlgAddUserToGroupLayout.createSequentialGroup()
                        .addComponent(jLabel5)
                        .addGap(0, 84, Short.MAX_VALUE))
                    .addGroup(dlgAddUserToGroupLayout.createSequentialGroup()
                        .addGap(10, 10, 10)
                        .addGroup(dlgAddUserToGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel7, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jLabel6, javax.swing.GroupLayout.Alignment.TRAILING))
                        .addGroup(dlgAddUserToGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(dlgAddUserToGroupLayout.createSequentialGroup()
                                .addGap(18, 18, 18)
                                .addComponent(txtAddUserToGroupGroup))
                            .addGroup(dlgAddUserToGroupLayout.createSequentialGroup()
                                .addGap(18, 18, 18)
                                .addComponent(txtAddUserToGroupUser))))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, dlgAddUserToGroupLayout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addComponent(btnAddUserToGroupOK, javax.swing.GroupLayout.PREFERRED_SIZE, 73, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnAddUserToGroupCancel, javax.swing.GroupLayout.PREFERRED_SIZE, 73, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap())
        );
        dlgAddUserToGroupLayout.setVerticalGroup(
            dlgAddUserToGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(dlgAddUserToGroupLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel5)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(dlgAddUserToGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel6)
                    .addComponent(txtAddUserToGroupUser, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(dlgAddUserToGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel7)
                    .addComponent(txtAddUserToGroupGroup, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(dlgAddUserToGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnAddUserToGroupCancel)
                    .addComponent(btnAddUserToGroupOK))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        dlgRemoveUserFromGroup.setTitle("Remove User From Group...");
        dlgRemoveUserFromGroup.setModal(true);

        jLabel8.setText("Please enter the user and group names.");

        jLabel9.setText("Username:");

        jLabel10.setText("Group name:");

        txtRemoveUserFromGroupUser.setText("jTextField1");

        txtRemoveUserFromGroupGroup.setText("jTextField2");

        btnRemoveUserFromGroupCancel.setText("Cancel");

        btnRemoveUserFromGroupOK.setText("OK");

        javax.swing.GroupLayout dlgRemoveUserFromGroupLayout = new javax.swing.GroupLayout(dlgRemoveUserFromGroup.getContentPane());
        dlgRemoveUserFromGroup.getContentPane().setLayout(dlgRemoveUserFromGroupLayout);
        dlgRemoveUserFromGroupLayout.setHorizontalGroup(
            dlgRemoveUserFromGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(dlgRemoveUserFromGroupLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(dlgRemoveUserFromGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(dlgRemoveUserFromGroupLayout.createSequentialGroup()
                        .addComponent(jLabel8)
                        .addGap(0, 84, Short.MAX_VALUE))
                    .addGroup(dlgRemoveUserFromGroupLayout.createSequentialGroup()
                        .addGap(10, 10, 10)
                        .addGroup(dlgRemoveUserFromGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel10, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jLabel9, javax.swing.GroupLayout.Alignment.TRAILING))
                        .addGap(18, 18, 18)
                        .addGroup(dlgRemoveUserFromGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(txtRemoveUserFromGroupUser)
                            .addComponent(txtRemoveUserFromGroupGroup)))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, dlgRemoveUserFromGroupLayout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addComponent(btnRemoveUserFromGroupOK, javax.swing.GroupLayout.PREFERRED_SIZE, 73, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnRemoveUserFromGroupCancel, javax.swing.GroupLayout.PREFERRED_SIZE, 73, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap())
        );

        dlgRemoveUserFromGroupLayout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {btnRemoveUserFromGroupCancel, btnRemoveUserFromGroupOK});

        dlgRemoveUserFromGroupLayout.setVerticalGroup(
            dlgRemoveUserFromGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(dlgRemoveUserFromGroupLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel8)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(dlgRemoveUserFromGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel9)
                    .addComponent(txtRemoveUserFromGroupUser, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(dlgRemoveUserFromGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel10)
                    .addComponent(txtRemoveUserFromGroupGroup, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(dlgRemoveUserFromGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnRemoveUserFromGroupCancel)
                    .addComponent(btnRemoveUserFromGroupOK))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        dlgDeleteUser.setTitle("Delete User...");
        dlgDeleteUser.setModal(true);

        jLabel11.setText("Please enter the username.");

        jLabel12.setText("Username:");

        txtDeleteUserUser.setText("jTextField1");

        btnDeleteUserCancel.setText("Cancel");

        btnDeleteUserOK.setText("OK");

        javax.swing.GroupLayout dlgDeleteUserLayout = new javax.swing.GroupLayout(dlgDeleteUser.getContentPane());
        dlgDeleteUser.getContentPane().setLayout(dlgDeleteUserLayout);
        dlgDeleteUserLayout.setHorizontalGroup(
            dlgDeleteUserLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(dlgDeleteUserLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(dlgDeleteUserLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(dlgDeleteUserLayout.createSequentialGroup()
                        .addGap(10, 10, 10)
                        .addComponent(jLabel12)
                        .addGap(18, 18, 18)
                        .addComponent(txtDeleteUserUser))
                    .addGroup(dlgDeleteUserLayout.createSequentialGroup()
                        .addComponent(jLabel11)
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, dlgDeleteUserLayout.createSequentialGroup()
                        .addGap(0, 129, Short.MAX_VALUE)
                        .addComponent(btnDeleteUserOK, javax.swing.GroupLayout.PREFERRED_SIZE, 73, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnDeleteUserCancel, javax.swing.GroupLayout.PREFERRED_SIZE, 73, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap())
        );
        dlgDeleteUserLayout.setVerticalGroup(
            dlgDeleteUserLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(dlgDeleteUserLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel11)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(dlgDeleteUserLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel12)
                    .addComponent(txtDeleteUserUser, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(dlgDeleteUserLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnDeleteUserCancel)
                    .addComponent(btnDeleteUserOK))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        dlgDeleteGroup.setTitle("Delete Group...");
        dlgDeleteGroup.setModal(true);

        jLabel13.setText("Please enter the group name.");

        jLabel14.setText("Group name:");

        txtDeleteGroupGroup.setText("jTextField1");
        txtDeleteGroupGroup.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                txtDeleteGroupGroupActionPerformed(evt);
            }
        });

        btnDeleteGroupCancel.setText("jButton1");

        btnDeleteGroupOK.setText("jButton2");

        javax.swing.GroupLayout dlgDeleteGroupLayout = new javax.swing.GroupLayout(dlgDeleteGroup.getContentPane());
        dlgDeleteGroup.getContentPane().setLayout(dlgDeleteGroupLayout);
        dlgDeleteGroupLayout.setHorizontalGroup(
            dlgDeleteGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(dlgDeleteGroupLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(dlgDeleteGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(dlgDeleteGroupLayout.createSequentialGroup()
                        .addGap(10, 10, 10)
                        .addComponent(jLabel14)
                        .addGap(18, 18, 18)
                        .addComponent(txtDeleteGroupGroup, javax.swing.GroupLayout.DEFAULT_SIZE, 189, Short.MAX_VALUE))
                    .addGroup(dlgDeleteGroupLayout.createSequentialGroup()
                        .addComponent(jLabel13)
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, dlgDeleteGroupLayout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addComponent(btnDeleteGroupOK, javax.swing.GroupLayout.PREFERRED_SIZE, 73, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnDeleteGroupCancel, javax.swing.GroupLayout.PREFERRED_SIZE, 73, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap())
        );
        dlgDeleteGroupLayout.setVerticalGroup(
            dlgDeleteGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(dlgDeleteGroupLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel13)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(dlgDeleteGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel14)
                    .addComponent(txtDeleteGroupGroup, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(dlgDeleteGroupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnDeleteGroupCancel)
                    .addComponent(btnDeleteGroupOK))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Groups");

        btnCreateUser.setText("Create User...");

        btnDeleteUser.setText("Delete User...");

        jSeparator1.setOrientation(javax.swing.SwingConstants.VERTICAL);

        btnCreateGroup.setText("Create Group...");
        btnCreateGroup.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnCreateGroupActionPerformed(evt);
            }
        });

        btnDeleteGroup.setText("Delete Group");

        bntAddToGroup.setText("Add User to Group...");

        btnRemoveFromGroup.setText("Remove User from Group...");

        lblTokenInfo.setFont(new java.awt.Font("Consolas", 0, 11)); // NOI18N
        lblTokenInfo.setText("HELP!");

        jPanel2.setBorder(javax.swing.BorderFactory.createTitledBorder("Groups"));

        groupList.setModel(new DefaultListModel());
        groupList.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                groupListMouseClicked(evt);
            }
        });
        jScrollPane1.setViewportView(groupList);

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 251, Short.MAX_VALUE)
                .addContainerGap())
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 219, Short.MAX_VALUE)
                .addContainerGap())
        );

        jPanel3.setBorder(javax.swing.BorderFactory.createTitledBorder("Users"));

        userList.setModel(new DefaultListModel());
        jScrollPane2.setViewportView(userList);

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane2)
                .addContainerGap())
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane2)
                .addContainerGap())
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(btnCreateUser)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(btnDeleteUser))
                            .addComponent(lblTokenInfo, javax.swing.GroupLayout.DEFAULT_SIZE, 210, Short.MAX_VALUE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(btnCreateGroup)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(btnDeleteGroup))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(bntAddToGroup)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(btnRemoveFromGroup))))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jPanel2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jPanel3, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {bntAddToGroup, btnCreateGroup, btnDeleteGroup, btnRemoveFromGroup});

        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(btnCreateUser)
                            .addComponent(btnDeleteUser))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(lblTokenInfo, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 52, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(btnCreateGroup)
                            .addComponent(btnDeleteGroup))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(bntAddToGroup)
                            .addComponent(btnRemoveFromGroup))))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jPanel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jPanel3, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void btnCreateGroupActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCreateGroupActionPerformed

    }//GEN-LAST:event_btnCreateGroupActionPerformed

    private void groupListMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_groupListMouseClicked
        updateUserList();
    }//GEN-LAST:event_groupListMouseClicked

    private void txtDeleteGroupGroupActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_txtDeleteGroupGroupActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_txtDeleteGroupGroupActionPerformed

    public void updateTokenLabel() {
        lblTokenInfo.setText(
            "User:   " + token.getSubject() + "\n" +
            "Issuer: " + token.getIssuer() + "\n" +
            "Groups: " + token.getGroups() + "\n" +
            "Owner:  " + token.getOwnership() + "\n");
    }
    
    public void updateGroupList() {
        DefaultListModel dlm = (DefaultListModel) groupList.getModel();
        
        dlm.clear();
        for (String s : token.getOwnership())
            dlm.addElement(s);
    }
    
    public void updateUserList() {
        DefaultListModel dlm = (DefaultListModel) userList.getModel();
        String group = groupList.getSelectedValue();

        if (group != null) {
            dlm.clear();
            for (String u : gc.listMembers(group, token))
                dlm.addElement(u);
        }
    }
    
    public static void go(UserToken t) {
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new GroupGUI(t).setVisible(true);
            }
        });
    }
    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(GroupGUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(GroupGUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(GroupGUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(GroupGUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        go(null);
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton bntAddToGroup;
    private javax.swing.JButton bntCreateUserOK;
    private javax.swing.JButton btnAddUserToGroupCancel;
    private javax.swing.JButton btnAddUserToGroupOK;
    private javax.swing.JButton btnCreateGroup;
    private javax.swing.JButton btnCreateGroupCancel;
    private javax.swing.JButton btnCreateGroupOK;
    private javax.swing.JButton btnCreateUser;
    private javax.swing.JButton btnCreateUserCancel;
    private javax.swing.JButton btnDeleteGroup;
    private javax.swing.JButton btnDeleteGroupCancel;
    private javax.swing.JButton btnDeleteGroupOK;
    private javax.swing.JButton btnDeleteUser;
    private javax.swing.JButton btnDeleteUserCancel;
    private javax.swing.JButton btnDeleteUserOK;
    private javax.swing.JButton btnRemoveFromGroup;
    private javax.swing.JButton btnRemoveUserFromGroupCancel;
    private javax.swing.JButton btnRemoveUserFromGroupOK;
    private javax.swing.JDialog dlgAddUserToGroup;
    private javax.swing.JDialog dlgCreateGroup;
    private javax.swing.JDialog dlgCreateUser;
    private javax.swing.JDialog dlgDeleteGroup;
    private javax.swing.JDialog dlgDeleteUser;
    private javax.swing.JDialog dlgRemoveUserFromGroup;
    private javax.swing.JList<String> groupList;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel11;
    private javax.swing.JLabel jLabel12;
    private javax.swing.JLabel jLabel13;
    private javax.swing.JLabel jLabel14;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JLabel lblTokenInfo;
    private javax.swing.JTextField txtAddUserToGroupGroup;
    private javax.swing.JTextField txtAddUserToGroupUser;
    private javax.swing.JTextField txtCreateGroupName;
    private javax.swing.JTextField txtCreateUserName;
    private javax.swing.JTextField txtDeleteGroupGroup;
    private javax.swing.JTextField txtDeleteUserUser;
    private javax.swing.JTextField txtRemoveUserFromGroupGroup;
    private javax.swing.JTextField txtRemoveUserFromGroupUser;
    private javax.swing.JList<String> userList;
    // End of variables declaration//GEN-END:variables
}
