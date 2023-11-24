import SwiftUI
struct OpenPortal: View {
    @Environment(\.presentationMode) var presentationMode: Binding<PresentationMode>
    let UrlSchemes = [
        "http", "https", "ssh", "git", "rsync", "ftp", "sftp",
        "redis", "jdbc", "mongodb", "postgresql", "mysql", "mysqlx"
    ]
    @FocusState private var isFocused: Bool

    @State var isProcessing = false
    @State var errorMessage = ""
    @State var serviceName = ""
    @State var serviceScheme = ""
    @State var serviceAddress = "localhost:10000"
    var body: some View {
        VStack(alignment: .leading) {
            Form {
                TextField("Name", text: $serviceName)
                    .focused($isFocused)
                    .onAppear(perform: {
                        //give focus to the text field on open
                        isFocused = true
                    })
                Text("A name for your portal")
                    .font(.caption)
                    .foregroundStyle(OckamSecondaryTextColor)

                TextField("Address", text: $serviceAddress)
                Text("IP address where your service is running")
                    .font(.caption)
                    .foregroundStyle(OckamSecondaryTextColor)

                Autocomplete(
                    suggestions: UrlSchemes,
                    label: "URL Scheme",
                    value: $serviceScheme
                )
                Text("URL scheme of the service, like http or ssh")
                    .font(.caption)
                    .foregroundStyle(OckamSecondaryTextColor)
            }
            .padding(.vertical, VerticalSpacingUnit*2)
            .padding(.horizontal, VerticalSpacingUnit*2)

            if !errorMessage.isEmpty {
                Text("Error: \(errorMessage)")
                    .foregroundColor(.red)
                    .padding(.vertical, VerticalSpacingUnit)
                    .padding(.horizontal, VerticalSpacingUnit)
            }

            Spacer()
            HStack {
                Spacer()
                Button(
                    action: {
                        self.closeWindow()
                    },
                    label: {
                        Text("Close")
                    })
                Button(
                    action: {
                        self.errorMessage = ""
                        isProcessing = true
                        let error = create_local_service(
                            self.serviceName,
                            self.serviceScheme == "" ? nil : self.serviceScheme,
                            self.serviceAddress
                        )
                        isProcessing = false
                        if error == nil {
                            self.errorMessage = ""
                            self.serviceName = ""
                            self.serviceScheme = ""
                            self.serviceAddress = "localhost:10000"
                            self.closeWindow()
                        } else {
                            self.errorMessage = String(cString: error.unsafelyUnwrapped)
                        }
                    },
                    label: {
                        Text("Create")
                    }
                )
                .disabled(!canCreateService() && !isProcessing)
                .keyboardShortcut(.defaultAction)
                .padding(10)
            }
            .background(OckamDarkerBackground)
        }
        .frame(width: 400)
    }
    func closeWindow() {
        self.presentationMode.wrappedValue.dismiss()
    }
    func canCreateService() -> Bool {
        return !self.serviceName.isEmpty && !self.serviceAddress.isEmpty
    }
}
struct CreateServiceView_Previews: PreviewProvider {
    static var previews: some View {
        OpenPortal()
    }
}
